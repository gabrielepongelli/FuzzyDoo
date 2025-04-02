import argparse
import sys
import logging
import subprocess
import shlex
import threading
from pathlib import Path
from typing import override

from ..agent import Agent, ExecutionContext
from ..utils.register import register
from .grpc_agent import GrpcClientAgent, GrpcServerAgent

from ..utils.errs import *


@register(Agent)
class CommandExecAgent(GrpcClientAgent):
    """Agent that execute a command on the server host."""

    # pylint: disable=useless-parent-delegation
    @override
    def set_options(self, **kwargs):
        """Set options for the agent.

        This method should be called before passing the agent to the engine.

        Args:
            kwargs: Additional keyword arguments. It must contain the following keys:
                - `'cmd'`: A string representing a command to execute along with all the arguments.
                - `'cwd'` (optional): A string representing the directory from which `cmd` is 
                        executed. Defaults to the current working directory.
                - `'env'` (optional): A dictionary representing the environment variables to set. 
                        Defaults to the environment of the current process.
                - `'through_shell'` (optional): Whether to run the command through a shell or not. 
                        Defaults to `False`.
                - `'shell_path'` (optional): The path to the shell to use in case `'through_shell'` 
                        is `True`. Defaults to `'/bin/bash'`.
                - `'attempts'` (optional): The number of attempts to re-run the command in case its 
                        return code is not `0`. Defaults to `5`.
                - `'max_execution_time'` (optional): The maximum amount of seconds the command must 
                        run before being killed and re-executed. Defaults to `60` seconds.
                - `'exec_on_epoch_start'` (optional): Whether to execute the command on every epoch 
                        start or not. Defaults to `False`.
                - `'exec_on_epoch_end'` (optional): Whether to execute the command on every epoch 
                        end or not. Defaults to `False`.
                - `'exec_on_test_start'` (optional): Whether to execute the command on every test 
                        start or not. Defaults to `False`.
                - `'exec_on_test_end'` (optional): Whether to execute the command on every test end 
                        or not. Defaults to `False`.
                - `'exec_on_redo'` (optional): Whether to execute the command before re-performing 
                        a test case or not. Defaults to `False`.
                - `'exec_on_fault'` (optional): Whether to execute the command after a fault has 
                        been found or not. Defaults to `False`.
                - `'exec_on_shutdown'` (optional): Whether to execute the command on shutdown or 
                        not. Defaults to `False`.
                - `'max_executions'` (optional): The number of times to execute the command, even 
                        if it should be executed multiple times (based on `'on_epoch_start'`, 
                        `'on_epoch_end'`, `'on_test_start'`, `'on_test_end'`, `'on_redo'`, 
                        `'on_fault'`, `'on_shutdown'`). Defaults to `0` (no limit).
                - `'reset_on_epoch_start'` (optional): Whether to reset the counter of executions 
                        on every epoch start or not (the command won't be runned on the reset if it 
                        was already executed `max_executions` times). Defaults to `False`.
                - `'reset_on_epoch_end'` (optional): Whether to reset the counter of executions on 
                        every epoch end or not (the command won't be runned on the reset if it was 
                        already executed `max_executions` times). Defaults to `False`.
                - `'reset_on_test_start'` (optional): Whether to reset the counter of executions on 
                        every test start or not (the command won't be runned on the reset if it was 
                        already executed `max_executions` times). Defaults to `False`.
                - `'reset_on_test_end'` (optional): Whether to reset the counter of executions on 
                        every test end or not (the command won't be runned on the reset if it was 
                        already executed `max_executions` times). Defaults to `False`.
                - `'reset_on_redo'` (optional): Whether to reset the counter of executions before 
                        re-performing a test case or not (the command won't be runned on the reset 
                        if it was already executed `max_executions` times). Defaults to `False`.
                - `'reset_on_fault'` (optional): Whether to reset the counter of executions after a 
                        fault has been found or not (the command won't be runned on the reset if it 
                        was already executed `max_executions` times). Defaults to `False`.
                - `'reset_on_shutdown'` (optional): Whether to reset the counter of executions on 
                        shutdown or not (the command won't be runned on the reset if it was already 
                        executed `max_executions` times). Defaults to `False`.

        Raises:
            AgentError: If some error occurred at the agent side. In this case the method 
                `stop_execution` is called.
        """
        super().set_options(**kwargs)

    @override
    def get_supported_paths(self, protocol: str) -> list[list[dict[str, str | bool]]]:
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
    def on_redo(self):
        return

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


class CommandExecServerAgent(GrpcServerAgent):
    """Server agent that execute a command on the server host."""

    DEFAULT_OPTIONS: dict[str, str | Path | int | bool | None] = {
        'cmd': None,
        'cwd': Path.cwd(),
        'env': None,
        'through_shell': False,
        'shell_path': Path('/bin/bash'),
        'attempts': 5,
        'max_execution_time': 60,
        'exec_on_epoch_start': False,
        'exec_on_epoch_end': False,
        'exec_on_test_start': False,
        'exec_on_test_end': False,
        'exec_on_redo': False,
        'exec_on_fault': False,
        'exec_on_shutdown': False,
        'max_executions': 0,
        'reset_on_epoch_start': False,
        'reset_on_epoch_end': False,
        'reset_on_test_start': False,
        'reset_on_test_end': False,
        'reset_on_redo': False,
        'reset_on_fault': False,
        'reset_on_shutdown': False,
    }

    options: dict[str, str | Path | int | bool | None]
    """Options currently set on the agent."""

    def __init__(self, **kwargs):
        super().__init__(None, **kwargs)

        self.options = dict(self.DEFAULT_OPTIONS)
        self.set_options(**kwargs)

        self._n_executions: int = 0

    def set_options(self, **kwargs):
        for key, val in kwargs.items():
            if key not in self.options:
                continue

            if key == 'shell_path':
                val = Path(kwargs[key])

            self.options[key] = val
            logging.info('Set %s = %s', key, val)

    def _run_cmd(self) -> bool:
        """Executes the configured command.

        This method runs the command specified in the `cmd` option, either directly or through a 
        shell, based on the `through_shell` option. If the command exceeds the maximum execution 
        time, it is terminated.

        Returns:
            bool: `True` if the command executes successfully (exit code `0`), `False` otherwise.
        """

        cmd = self.options['cmd']
        if not self.options['through_shell']:
            cmd = shlex.split(cmd)

        proc = subprocess.Popen(
            args=cmd,
            shell=self.options['through_shell'],
            executable=self.options['shell_path'] if self.options['through_shell'] else cmd[0],
            cwd=self.options['cwd'],
            env=self.options['env'],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        # thread function to capture the output
        def display_output():
            for line in iter(proc.stdout.readline, ''):
                logging.info(line.strip())
            proc.stdout.close()

        t = threading.Thread(target=display_output)
        t.start()

        try:
            ret = proc.wait(timeout=self.options['max_execution_time'])
        except subprocess.TimeoutExpired:
            proc.kill()
            logging.error('Command execution timed out after %d seconds', self.options['max_execution_time'])
            t.join()
            return False

        t.join()
        if ret != 0:
            logging.error('Command execution failed with exit code %d', ret)
            return False

        return True

    def _run_on_method(self, method: str):
        """Executes the command based on the specified method.

        This method checks if the command should be executed based on the options set for the given 
        method. It also ensures that the command is not executed more than the maximum allowed 
        number of times (`max_executions`). If the command fails, it retries up to the specified 
        number of attempts (`attempts`). Additionally, it resets the execution counter if the 
        corresponding reset option is enabled.

        Args:
            method: The method name (e.g., 'on_epoch_start', 'on_test_end') that determines whether 
                the command should be executed.
        """

        if self.options['exec_' + method] \
                and (self.options['max_executions'] <= 0
                     or self._n_executions < self.options['max_executions']):
            for attempt in range(self.options['attempts']):
                logging.info('Attempt #%d', attempt + 1)
                if self._run_cmd():
                    self._n_executions += 1
                    break

        if self.options['reset_' + method]:
            self._n_executions = 0

    @override
    def reset(self):
        self.options = dict(self.DEFAULT_OPTIONS)
        self._n_executions = 0

    @override
    def on_epoch_start(self, ctx: ExecutionContext):
        self._run_on_method('on_epoch_start')

    @override
    def on_epoch_end(self):
        self._run_on_method('on_epoch_end')

    @override
    def on_test_start(self, ctx: ExecutionContext):
        self._run_on_method('on_test_start')

    @override
    def on_test_end(self):
        self._run_on_method('on_test_end')

    @override
    def on_redo(self):
        self._run_on_method('on_redo')

    @override
    def on_fault(self):
        self._run_on_method('on_fault')

    @override
    def on_shutdown(self):
        self._run_on_method('on_shutdown')


__all__ = ['CommandExecAgent']


def main():
    parser = argparse.ArgumentParser(
        description='Agent that execute a command on the server host.')
    parser.add_argument('--ip', type=str, help='IP address to listen on')
    parser.add_argument('--port', type=int, help='Port to listen on')

    args = parser.parse_args()

    if not args.ip or not args.port:
        sys.stderr.write("Error: No IP address and port specified\n")
        sys.exit(1)

    logging.basicConfig(level=logging.DEBUG, format="[%(levelname)s] - %(message)s")

    agent = CommandExecServerAgent(address=args.ip, port=args.port)
    agent.serve()
