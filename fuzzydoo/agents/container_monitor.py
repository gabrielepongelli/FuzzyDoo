import argparse
import sys
import logging
import subprocess
from typing import override

from ..agent import Agent, AgentError, ExecutionContext
from ..utils.register import register
from .grpc_agent import GrpcClientAgent, GrpcServerAgent


@register(Agent)
class ContainerMonitorAgent(GrpcClientAgent):
    """Monitor that checks whether a docker container is running or not."""

    # pylint: disable=useless-parent-delegation
    @override
    def set_options(self, **kwargs):
        """Set options for the agent.

        This method should be called before passing the agent to the engine.

        Args:
            kwargs: Additional keyword arguments. It must contain the following keys:
                `'containers'`: A list of strings representing the names of the containers to 
                    monitor.

        Raises:
            AgentError: If some error occurred at the agent side. In this case the method 
                `stop_execution` is called.
        """
        super().set_options(**kwargs)

    @override
    def on_test_start(self, ctx: ExecutionContext):
        return

    @override
    def on_test_end(self):
        return

    @override
    def skip_epoch(self, ctx: ExecutionContext) -> bool:
        return False

    @override
    def redo_test(self) -> bool:
        return False

    @override
    def on_fault(self):
        return

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


class ContainerMonitorServerAgent(GrpcServerAgent):
    """Monitor server agent that checks whether a docker container is running or not.

    It does this using `docker inspect`.
    """

    DEFAULT_OPTIONS: dict[str, list[str]] = {
        'containers': []
    }

    def __init__(self, **kwargs):
        super().__init__(None, **kwargs)

        self.options = dict(self.DEFAULT_OPTIONS)
        self.set_options(**kwargs)

    @override
    def set_options(self, **kwargs):
        if 'containers' in kwargs:
            self.options['containers'] = kwargs['containers']
            logging.info('Set %s = %s', 'containers', self.options['containers'])

    @override
    def reset(self):
        self.options = dict(self.DEFAULT_OPTIONS)

    def _is_running(self, container: str) -> bool:
        """Check whether the specified container is running.

        Args:
            container: The name of the container to monitor.

        Returns:
            bool: `True` if the container is running, `False` otherwise.

        Raises:
            AgentError: If an error occurred while running the `docker inspect` command.
        """

        try:
            result = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Running}}", container],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
            )
        except subprocess.CalledProcessError as e:
            err_msg = str(e.stderr).strip()
            logging.error(err_msg)
            raise AgentError(err_msg) from e

        is_running = result.stdout.strip()
        if is_running == "true":
            logging.info('Container %s running', self.options['container_name'])
            return True

        if is_running == "false":
            logging.info('Container %s not running', self.options['container_name'])
            return False

        logging.error("Unexpected output: %s", is_running)
        raise AgentError("Unexpected output: " + is_running)

    def _get_logs(self, container: str) -> bytes:
        """Get the logs of the specified container.

        Args:
            container: The name of the container.

        Returns:
            bytes: The logs of the container.

        Raises:
            AgentError: If an error occurred while running the `docker logs` command.
        """

        try:
            result = subprocess.run(
                ["docker", "logs", container],
                stdout=subprocess.PIPE, text=True, check=True
            )
        except subprocess.CalledProcessError as e:
            err_msg = str(e.stderr).strip()
            logging.error(err_msg)
            raise AgentError(err_msg) from e

        return result.stdout.encode()

    @override
    def fault_detected(self) -> bool:
        if not self.options['containers']:
            logging.error("No container name specified")
            raise AgentError("No container name specified")

        for container in self.options['containers']:
            if not self._is_running(container):
                return True

        return False

    @override
    def get_data(self) -> list[tuple[str, bytes]]:
        res = []
        for container in self.options['containers']:
            logs = self._get_logs(container)
            record_name = container + ".log.txt"
            res.append((record_name, logs))
        return res


__all__ = ['ContainerMonitorAgent']


def main():
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
