import argparse
import sys
import os
import logging
import subprocess
import re
import time
from pathlib import Path
from typing import override

from ..agent import Agent, ExecutionContext
from ..utils.register import register
from ..utils.other import run_as_root
from .grpc_agent import GrpcClientAgent, GrpcServerAgent

from ..utils.errs import *


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
                - `'clean_volumes_on_restart'` (optional): Whether to remove all the volumes in the 
                        docker compose setup after on each restart. Defaults to `False`. 
                - `'restart_on_epoch'` (optional): Whether the containers in the compose setting 
                        should be started and stopped respectively at the beginning and at the end 
                        of every epoch. Defaults to `False`.
                - `'restart_on_test'` (optional): Whether the containers in the compose setting 
                        should be started and stopped respectively at the beginning and at the end of every test case or not. Defaults to `False`.
                - `'restart_on_redo'` (optional): Whether the containers in the compose setting 
                        should be restarted before re-performing a test case or not. Defaults to 
                        `False`.
                - `'restart_on_fault'` (optional): Whether the containers in the compose setting 
                        should be restarted at the end of a test case after a fault has been found 
                        or not (even if `restart_on_test` is set to `False`). Defaults to `False`.

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
        'clean_volumes_on_restart': False,
        'restart_on_epoch': False,
        'restart_on_test': False,
        'restart_on_redo': False,
        'restart_on_fault': False,
    }

    options: dict[str, Path | bool | None]
    """Options currently set on the agent."""

    def __init__(self, **kwargs):
        super().__init__(None, **kwargs)

        self.options = dict(self.DEFAULT_OPTIONS)
        self.set_options(**kwargs)

        self._fault_detected: bool = False
        self._signal_shutdown: bool = False

    def set_options(self, **kwargs):
        for key, val in kwargs.items():
            if key not in self.options:
                continue

            if key == 'compose_yaml_path':
                val = Path(kwargs[key])

            self.options[key] = val
            logging.info('Set %s = %s', key, val)

    @override
    def reset(self):
        self.options = dict(self.DEFAULT_OPTIONS)
        self._fault_detected = False
        self._signal_shutdown = False

    def _is_running(self) -> bool:
        """Check whether the docker compose setup is already running."""

        if self.options['compose_yaml_path'] is None:
            msg = "No docker-compose.yaml path specified"
            logging.error(msg)
            raise AgentError(msg)

        try:
            result: subprocess.CompletedProcess[str] = subprocess.run(
                ["docker", "compose", "-f", self.options['compose_yaml_path'], "ps", "-q"],
                capture_output=True, text=True, check=True
            )
        except subprocess.CalledProcessError as e:
            self._signal_shutdown = True
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
                capture_output=True, text=True, check=True
            )
        except subprocess.CalledProcessError as e:
            self._signal_shutdown = True
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

        compose_down_cmd = ["docker", "compose", "-f", self.options['compose_yaml_path'], "down"]
        if self.options['clean_volumes_on_restart']:
            compose_down_cmd.append("-v")
        try:
            subprocess.run(compose_down_cmd, capture_output=True, text=True, check=True)
        except subprocess.CalledProcessError as e1:
            # we need to restart the docker service before removing the network
            try:
                # get the root path of docker
                res = subprocess.run(["docker", "info"], capture_output=True, text=True, check=True)
                docker_root_dir = re.search(r"Docker Root Dir:\s*(.*)", res.stdout)
                if not docker_root_dir:
                    err_msg = str(e1.stderr).strip()
                    logging.error(err_msg)
                    raise AgentError(err_msg) from e1

                # restart the docker service
                service_restarted = False
                if 'snap' in docker_root_dir.group(1):
                    subprocess.run(
                        ["snap", "restart", "docker"],
                        capture_output=True, text=True, check=True
                    )

                    start = time.time()
                    while time.time() - start < 60 and not service_restarted:
                        res = subprocess.run(
                            ["snap", "services"],
                            capture_output=True, text=True, check=True
                        )

                        for line in res.stdout.splitlines():
                            if "docker.dockerd" in line and "active" in line:
                                service_restarted = True
                                break

                        time.sleep(0.1)

                else:
                    subprocess.run(
                        ["systemctl", "restart", "docker.service"],
                        capture_output=True, text=True, check=True
                    )

                    start = time.time()
                    while time.time() - start < 60 and not service_restarted:
                        res = subprocess.run(
                            ["systemctl", "status", "docker"],
                            capture_output=True, text=True, check=True
                        )

                        for line in res.stdout.splitlines():
                            if "Active" in line and "active (running)" in line:
                                service_restarted = True
                                break

                        time.sleep(0.1)

                if not service_restarted:
                    self._signal_shutdown = True
                    err_msg = "Could not restart the docker service"
                    logging.error(err_msg)
                    raise AgentError(err_msg) from e1

                subprocess.run(compose_down_cmd, capture_output=True, text=True, check=True)
            except subprocess.CalledProcessError as e2:
                self._signal_shutdown = True
                err_msg = str(e2.stderr).strip()
                logging.error(err_msg)
                raise AgentError(err_msg) from e2

        logging.info("Docker compose setup stopped")

    @override
    def on_epoch_start(self, ctx: ExecutionContext):
        if self.options['restart_on_epoch'] and not self._is_running():
            self._start_compose()

    @override
    def on_epoch_end(self):
        if self.options['restart_on_epoch']:
            self._stop_compose()

    @override
    def on_test_start(self, ctx: ExecutionContext):
        if (self.options['restart_on_test'] or self._fault_detected) and not self._is_running():
            self._fault_detected = False
            self._start_compose()

    @override
    def on_test_end(self):
        if self.options['restart_on_test'] or self._fault_detected:
            self._stop_compose()

    @override
    def on_redo(self):
        if self.options['restart_on_redo']:
            self._stop_compose()
            self._start_compose()

    @override
    def on_fault(self):
        self._fault_detected = self.options['restart_on_fault']

    @override
    def on_shutdown(self):
        self._stop_compose()

    @override
    def stop_execution(self) -> bool:
        return self._signal_shutdown


__all__ = ['ComposeRestartAgent']


def main():
    parser = argparse.ArgumentParser(
        description='Agent that restarts all the docker containers in a docker compose setup.')
    parser.add_argument('--ip', type=str, help='IP address to listen on')
    parser.add_argument('--port', type=int, help='Port to listen on')

    args = parser.parse_args()

    if os.geteuid() != 0:
        run_as_root()

    if not args.ip or not args.port:
        sys.stderr.write("Error: No IP address and port specified\n")
        sys.exit(1)

    logging.basicConfig(level=logging.DEBUG, format="[%(levelname)s] - %(message)s")

    agent = ComposeRestartServerAgent(address=args.ip, port=args.port)
    agent.serve()
