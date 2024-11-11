import logging
import subprocess
from typing import override

from ..agent import AgentError, ExecutionContext
from .grpc_agent import GrpcClientAgent, GrpcServerAgent


class ComposeRestartAgent(GrpcClientAgent):
    """Agent that restarts all the docker containers in a docker compose setup."""

    # pylint: disable=useless-parent-delegation
    @override
    def set_options(self, **kwargs):
        """Set options for the agent.

        This method should be called before passing the agent to the engine.

        Args:
            kwargs: Additional keyword arguments. It must contain the following keys:
                'compose_yaml_path': The path to the `docker-compose.yaml` file.
                'restart_anyway' (optional): Whether the containers in the compose setting should 
                    be restarted in `on_test_start` even if they are already running. Defaults to 
                    `False`.

        Raises:
            AgentError: If some error occurred at the agent side. In this case the method 
                `stop_execution` is called.
        """
        super().set_options(**kwargs)

    @override
    def on_test_end(self):
        return

    @override
    def get_data(self) -> list[tuple[str, bytes]]:
        return []

    @override
    def skip_epoch(self, ctx: ExecutionContext) -> bool:
        return False

    @override
    def redo_test(self) -> bool:
        return False

    @override
    def fault_detected(self) -> bool:
        return False

    @override
    def stop_execution(self) -> bool:
        return False


class ComposeRestartServerAgent(GrpcServerAgent):
    """Server agent that restarts all the docker containers in a docker compose setup.

    It does this using:
    - `docker compose -f <compose_yaml_path> up -d` to start the containers in the compose setup.
    - `docker compose -f <compose_yaml_path> down` to stop the containers in the compose setup.
    - `docker compose -f <compose_yaml_path> ps -q` to check if the compose setup is already 
        running.
    """

    def __init__(self, **kwargs):
        super().__init__(None, **kwargs)

        self._compose_yaml_path: str | None = kwargs.get(
            'compose_yaml_path', None)
        self._restart_anyway: bool = kwargs.get('restart_anyway', False)

    def set_options(self, **kwargs):
        if 'compose_yaml_path' in kwargs:
            self._compose_yaml_path = kwargs['compose_yaml_path']
            logging.info('Set %s = %s', 'compose_yaml_path',
                         self._compose_yaml_path)

        if 'restart_anyway' in kwargs:
            self._restart_anyway = kwargs['restart_anyway']
            logging.info('Set %s = %s', 'restart_anyway', self._restart_anyway)

    def _is_running(self) -> bool:
        """Check whether the docker compose setup is already running."""

        if self._compose_yaml_path is None:
            logging.error("No docker-compose.yaml path specified")
            raise AgentError("No docker-compose.yaml path specified")

        try:
            result = subprocess.run(
                ["docker", "compose", "-f", self._compose_yaml_path, "ps", "-q"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
            )
        except subprocess.CalledProcessError as e:
            err_msg = str(e.stderr).strip()
            logging.error(err_msg)
            raise AgentError(err_msg) from e

        return result.stdout.strip() != ""

    def _restart_compose(self):
        """Restart all the containers in the docker compose setup."""

        if self._compose_yaml_path is None:
            logging.error("No docker-compose.yaml path specified")
            raise AgentError("No docker-compose.yaml path specified")

        try:
            subprocess.run(
                ["docker", "compose", "-f", self._compose_yaml_path, "down"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
            )
        except subprocess.CalledProcessError as e:
            err_msg = str(e.stderr).strip()
            logging.error(err_msg)
            raise AgentError(err_msg) from e

        try:
            subprocess.run(
                ["docker", "compose", "-f", self._compose_yaml_path, "up", "-d"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
            )
        except subprocess.CalledProcessError as e:
            err_msg = str(e.stderr).strip()
            logging.error(err_msg)
            raise AgentError(err_msg) from e

    @override
    def on_test_start(self, ctx: ExecutionContext):
        if self._restart_anyway or not self._is_running():
            self._restart_compose()

    @override
    def on_fault(self):
        self._restart_compose()


def main():
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description='Agent that restarts all the docker containers in a docker compose setup.')
    parser.add_argument('--ip', type=str, help='IP address to listen on')
    parser.add_argument('--port', type=int, help='Port to listen on')

    args = parser.parse_args()
    if not args.ip or not args.port:
        sys.stderr.write("Error: No IP address and port specified\n")
        sys.exit(1)

    logging.basicConfig(level=logging.DEBUG,
                        format="[%(levelname)s] - %(message)s")

    agent = ComposeRestartServerAgent(address=args.ip, port=args.port)
    agent.serve()
