import argparse
import sys
import logging
import subprocess
import time
from typing import override

from ..agent import Agent, ExecutionContext
from ..utils.register import register
from .grpc_agent import GrpcClientAgent, GrpcServerAgent

from ..utils.errs import *


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
                - `'containers'`: A list of strings representing the names of the containers to 
                        monitor.

        Raises:
            AgentError: If some error occurred at the agent side. In this case the method 
                `stop_execution` is called.
        """
        super().set_options(**kwargs)

    @override
    def on_epoch_start(self, ctx: ExecutionContext):
        return

    @override
    def on_epoch_end(self):
        return

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
    def on_redo(self):
        return

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

    options: dict[str, list[str]]
    """Options currently set on the agent."""

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

    def _get_exit_code(self, container: str) -> int | None:
        """_summary_

        _extended_summary_

        Args:
            container (str): _description_

        Returns:
            int: _description_
        """

        try:
            result = subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Status}}:{{.State.ExitCode}}", container],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
            )
        except subprocess.CalledProcessError as e:
            err_msg = str(e.stderr).strip()
            logging.error(err_msg)
            raise AgentError(err_msg) from e

        if 'exited' in result.stdout:
            return result.stdout.strip().split(':')[1]
        return None

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
            return True

        if is_running == "false":
            return False

        raise AgentError("Unexpected output: " + is_running)

    def _get_logs(self, container: str) -> bytes:
        """Get the logs of the specified container.

        Args:
            container: The name of the container.

        Returns:
            bytes: The standard output and the standard error of the container.

        Raises:
            AgentError: If an error occurred while running the `docker logs` command.
        """

        try:
            result = subprocess.run(
                ["docker", "logs", container], text=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
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

        # keep checking for 5 seconds
        not_running = set()
        start = time.time()
        while time.time() - start < 5:
            for container in self.options['containers']:
                if not self._is_running(container):
                    not_running.add(container)

        for container in self.options['containers']:
            state = 'not running' if container in not_running else 'running'
            logging.info('Container %s %s', container, state)

        return bool(not_running)

    @override
    def get_data(self) -> list[tuple[str, bytes]]:
        res = []
        exit_codes = b""
        for container in self.options['containers']:
            output = self._get_logs(container)

            record_name = container + ".log.txt"
            res.append((record_name, output))

            exit_code = self._get_exit_code(container)
            exit_codes += f"{container}: {exit_code or ''}\n".encode()

        record_name = "exit_codes.txt"
        res.append((record_name, exit_codes))

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

    logging.basicConfig(level=logging.DEBUG, format="[%(levelname)s] - %(message)s")

    agent = ContainerMonitorServerAgent(address=args.ip, port=args.port)
    agent.serve()
