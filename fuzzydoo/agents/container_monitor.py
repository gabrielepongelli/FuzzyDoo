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
                `'container_name'`: The name of the container to monitor.

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
    def get_data(self) -> list[tuple[str, bytes]]:
        return []

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

    DEFAULT_OPTIONS: dict[str, str | None] = {
        'container_name': None
    }

    def __init__(self, **kwargs):
        super().__init__(None, **kwargs)

        self.options = dict(self.DEFAULT_OPTIONS)
        self.set_options(**kwargs)

    @override
    def set_options(self, **kwargs):
        if 'container_name' in kwargs:
            self.options['container_name'] = kwargs['container_name']
            logging.info('Set %s = %s', 'container_name', self.options['container_name'])

    @override
    def reset(self):
        self.options = dict(self.DEFAULT_OPTIONS)

    @override
    def fault_detected(self) -> bool:
        if self.options['container_name'] is None:
            logging.error("No container name specified")
            raise AgentError("No container name specified")

        try:
            result = subprocess.run(
                ["docker", "inspect", "--format",
                    "{{.State.Running}}", self.options['container_name']],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
            )
        except subprocess.CalledProcessError as e:
            err_msg = str(e.stderr).strip()
            logging.error(err_msg)
            raise AgentError(err_msg) from e

        is_running = result.stdout.strip()
        if is_running == "true":
            logging.info('Container %s running', self.options['container_name'])
            return False  # fault not detected

        if is_running == "false":
            logging.info('Container %s not running', self.options['container_name'])
            return True  # fault detected

        logging.error("Unexpected output: %s", is_running)
        raise AgentError("Unexpected output: " + is_running)


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
