import logging
import subprocess

from ..agent import AgentError
from .grpc_agent import GrpcClientAgent, GrpcServerAgent


class ContainerMonitorAgent(GrpcClientAgent):
    """Monitor that checks whether a docker container is running or not."""

    # pylint: disable=useless-parent-delegation
    def set_options(self, **kwargs):
        """Set options for the agent.

        This method should be called before passing the agent to the engine.

        Args:
            kwargs: Additional keyword arguments. It must contain the following keys:
                'container_name': The name of the container to monitor.

        Raises:
            AgentError: If some error occurred at the agent side. In this case the method 
                `stop_execution` is called.
        """
        super().set_options(**kwargs)

    def on_test_start(self, path: str):
        return

    def on_test_end(self):
        return

    def get_data(self) -> list[tuple[str, bytes]]:
        return []

    def skip_epoch(self, path: str) -> bool:
        return False

    def redo_test(self) -> bool:
        return False

    def on_fault(self):
        return

    def on_shutdown(self):
        return

    def stop_execution(self) -> bool:
        return False


class ContainerMonitorServerAgent(GrpcServerAgent):
    """Monitor server agent that checks whether a docker container is running or not.

    It does this using `docker inspect`.
    """

    def __init__(self, **kwargs):
        super().__init__(None, **kwargs)

        self._container_name: str | None = kwargs.get('container_name', None)

    def set_options(self, **kwargs):
        if 'container_name' in kwargs:
            self._container_name = kwargs['container_name']
            logging.info('Set %s = %s', 'container_name', self._container_name)

    def fault_detected(self) -> bool:
        if self._container_name is None:
            logging.error("No container name specified")
            raise AgentError("No container name specified")

        try:
            result = subprocess.run(
                ["docker", "inspect", "--format",
                    "{{.State.Running}}", self._container_name],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
            )
        except subprocess.CalledProcessError as e:
            err_msg = str(e.stderr).strip()
            logging.error(err_msg)
            raise AgentError(err_msg) from e

        is_running = result.stdout.strip()
        if is_running == "true":
            logging.info('Container %s running', self._container_name)
            return True

        if is_running == "false":
            logging.info('Container %s not running', self._container_name)
            return False

        logging.error("Unexpected output: %s", is_running)
        raise AgentError("Unexpected output: " + is_running)


def main():
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description='Agent that checks if a container is running.')
    parser.add_argument('--ip', type=str, help='IP address to listen on')
    parser.add_argument('--port', type=int, help='Port to listen on')

    args = parser.parse_args()
    if not args.ip or not args.port:
        sys.stderr.write("Error: No IP address and port specified\n")
        sys.exit(1)

    logging.basicConfig(level=logging.DEBUG,
                        format="[%(levelname)s] - %(message)s")

    agent = ContainerMonitorServerAgent(address=args.ip, port=args.port)
    agent.serve()
