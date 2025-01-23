import logging
import subprocess
import re
import time
from pathlib import Path
from typing import override

from ..agent import Agent, AgentError, ExecutionContext
from ..utils.register import register
from .grpc_agent import GrpcClientAgent, GrpcServerAgent


@register(Agent)
class ComposeRestartAgent(GrpcClientAgent):
    """Agent that restarts all the docker containers in a docker compose setup."""

    # pylint: disable=useless-parent-delegation
    @override
    def set_options(self, **kwargs):
        """Set options for the agent.

        This method should be called before passing the agent to the engine.

        Args:
            kwargs: Additional keyword arguments. It must contain the following keys:
                - `'compose_yaml_path'`: The path to the `docker-compose.yaml` file.
                - `'restart_anyway'` (optional): Whether the containers in the compose setting 
                    should be restarted in `on_test_start` even if they are already running. 
                    Defaults to `False`.

        Raises:
            AgentError: If some error occurred at the agent side. In this case the method 
                `stop_execution` is called.
        """
        super().set_options(**kwargs)

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

    @override
    def start(self, pub_id: int):
        return

    @override
    def stop(self, pub_id: int):
        return

    @override
    def send(self, pub_id: int, data: bytes):
        return

    @override
    def receive(self, pub_id: int) -> bytes:
        return b""

    @override
    def data_available(self, pub_id: int) -> bool:
        return False


class ComposeRestartServerAgent(GrpcServerAgent):
    """Server agent that restarts all the docker containers in a docker compose setup.

    It does this using:
    - `docker compose -f <compose_yaml_path> up -d` to start the containers in the compose setup.
    - `docker compose -f <compose_yaml_path> down` to stop the containers in the compose setup.
    - `docker compose -f <compose_yaml_path> ps -q` to check if the compose setup is already 
        running.
    """

    DEFAULT_OPTIONS: dict[str, Path | bool | None] = {
        'compose_yaml_path': None,
        'restart_anyway': False
    }

    def __init__(self, **kwargs):
        super().__init__(None, **kwargs)

        self.options = dict(self.DEFAULT_OPTIONS)
        self.set_options(**kwargs)

        self._fault_detected: bool = False

    def set_options(self, **kwargs):
        if 'compose_yaml_path' in kwargs:
            self.options['compose_yaml_path'] = Path(kwargs['compose_yaml_path'])
            logging.info('Set %s = %s', 'compose_yaml_path', self.options['compose_yaml_path'])

        if 'restart_anyway' in kwargs:
            self.options['restart_anyway'] = kwargs['restart_anyway']
            logging.info('Set %s = %s', 'restart_anyway', self.options['restart_anyway'])

    @override
    def reset(self):
        self.options = dict(self.DEFAULT_OPTIONS)
        self._fault_detected = False

    def _is_running(self) -> bool:
        """Check whether the docker compose setup is already running."""

        if self.options['compose_yaml_path'] is None:
            msg = "No docker-compose.yaml path specified"
            logging.error(msg)
            raise AgentError(msg)

        try:
            result: subprocess.CompletedProcess[str] = subprocess.run(
                ["docker", "compose", "-f", self.options['compose_yaml_path'], "ps", "-q"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
            )
        except subprocess.CalledProcessError as e:
            err_msg = str(e.stderr).strip()
            logging.error(err_msg)
            raise AgentError(err_msg) from e

        return result.stdout.strip() != ""

    def _start_compose(self):
        """Start all the containers in the docker compose setup."""

        logging.info("Starting docker compose setup...")

        if self.options['compose_yaml_path'] is None:
            logging.error("No docker-compose.yaml path specified")
            raise AgentError("No docker-compose.yaml path specified")

        try:
            subprocess.run(
                ["docker", "compose", "-f", self.options['compose_yaml_path'], "up", "-d"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
            )
        except subprocess.CalledProcessError as e:
            err_msg = str(e.stderr).strip()
            logging.error(err_msg)
            raise AgentError(err_msg) from e

        logging.info("Docker compose setup started")

    def _stop_compose(self):
        """Stop all the containers in the docker compose setup."""

        logging.info("Stopping docker compose setup...")

        if self.options['compose_yaml_path'] is None:
            logging.error("No docker-compose.yaml path specified")
            raise AgentError("No docker-compose.yaml path specified")

        try:
            subprocess.run(
                ["docker", "compose", "-f", self.options['compose_yaml_path'], "down"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
            )
        except subprocess.CalledProcessError as e1:
            # we need to restart the docker service before removing the network
            try:
                # get the root path of docker
                res = subprocess.run(
                    ["docker", "info"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
                )
                docker_root_dir = re.search(r"Docker Root Dir:\s*(.*)", res.stdout)
                if not docker_root_dir:
                    err_msg = str(e1.stderr).strip()
                    logging.error(err_msg)
                    raise AgentError(err_msg) from e1

                # restart the docker service
                if 'snap' in docker_root_dir.group(1):
                    subprocess.run(
                        ["snap", "restart", "docker"],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
                    )
                else:
                    subprocess.run(
                        ["systemctl", "restart", "docker.service"],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
                    )

                time.sleep(1)

                subprocess.run(
                    ["docker", "compose", "-f", self.options['compose_yaml_path'], "down"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
                )
            except subprocess.CalledProcessError as e2:
                err_msg = str(e2.stderr).strip()
                logging.error(err_msg)
                raise AgentError(err_msg) from e2

        logging.info("Docker compose setup stopped")

    @override
    def on_test_start(self, ctx: ExecutionContext):
        if not self._is_running():
            self._start_compose()
        elif self.options['restart_anyway']:
            self._stop_compose()
            self._start_compose()

    @override
    def on_test_end(self):
        if self.options['restart_anyway'] or self._fault_detected:
            self._fault_detected = False
            self._stop_compose()

    @override
    def on_fault(self):
        self._fault_detected = True

    @override
    def on_shutdown(self):
        self._stop_compose()


__all__ = ['ComposeRestartAgent']


def main():
    import argparse
    import sys
    import os

    parser = argparse.ArgumentParser(
        description='Agent that restarts all the docker containers in a docker compose setup.')
    parser.add_argument('--ip', type=str, help='IP address to listen on')
    parser.add_argument('--port', type=int, help='Port to listen on')

    args = parser.parse_args()

    if os.geteuid() != 0:
        sys.stderr.write(
            "You need root permissions to run this script. To solve this problem execute this script like this:\n\n")
        sys.stderr.write("\tsudo $(which compose-restart)\n\n")
        sys.exit(1)

    if not args.ip or not args.port:
        sys.stderr.write("Error: No IP address and port specified\n")
        sys.exit(1)

    logging.basicConfig(level=logging.DEBUG,
                        format="[%(levelname)s] - %(message)s")

    agent = ComposeRestartServerAgent(address=args.ip, port=args.port)
    agent.serve()
