import logging
import time
from dataclasses import dataclass

from .protocol import ProtocolPath
from .publisher import PublisherSource
from .utils.errs import FuzzyDooError
from .utils.register import ClassRegister


class AgentError(FuzzyDooError):
    """Generic error for the `Agent` interface."""


class UnknownAgentError(AgentError):
    """Exception raised when an unknown agent type is encountered."""


@dataclass
class ExecutionContext:
    """Class representing the context in which a method is executed."""

    protocol_name: str
    """Name of the protocol on which FuzzyDoo is executed."""

    path: ProtocolPath
    """The specific protocol path on which the agent method is invoked."""


class Agent(PublisherSource):
    """A remote or local agent.

    Agents are independent programs running somewhere (in the same machine or not).

    The following is a simple pseudo-code that helps to understand when each method is called:
    ```python
    agent = SomeAgent()

    options = # some options
    agent.set_options(**options)

    # Do some other configurations...

    protocol_name = "Some protocol"
    paths = agent.get_supported_paths(protocol_name)

    # Start the fuzzing run
    for epoch in epochs:
        # Do some stuffs...

        ctx = # some context
        if agent.skip_epoch(ctx):
            continue

        # Do some other stuffs...

        agent.on_test_start(ctx)
        # Test case started
        with test_case:
            # Execute some actions...

            if agent.redo_test():
                # exit from test case

            if agent.fault_detected():
                agent.on_fault()

                # ....

                data = agent.get_data()

        # Test case stopped

        agent.on_test_end()

    # Fuzzing run ended
    agent.on_shutdown()
    ```

    In addition to this code, if each of the `Agent` methods called in this pseudo-code raises an 
    exception, the method `stop_execution` is called with the following consequences:
    - If its result is `True`, the program will call `on_shutdown` and nothing else.
    - If its result is `False`, the program will handle the exception and **continue the execution**.

    To add some behaviour, just override the appropriate method.

    Attributes:
        name: The name of the agent.
        wait_start_time: Seconds to wait after calling `on_test_start` before continuing. This can 
            be useful if an agent requires some time to start.
    """

    @classmethod
    def from_name(cls, name: str, *args, **kwargs) -> "Agent":
        """Create a new `Agent` instance from the specified name.

        Args:
            name: The name of the agent to instanciate.
            args: Additional positional arguments that will be passed directly to the constructor 
                of the specified agent.
            kwargs: Additional keyword arguments that will be passed directly to the constructor of 
                the specified agent.

        Returns:
            Agent: An instance of the specified agent.

        Raises:
            UnknownAgentError: If no agent with the given name exists.
        """

        try:
            return ClassRegister["Agent"].get('Agent', name)(*args, **kwargs)
        except ValueError as e:
            raise UnknownAgentError(f"Unknown agent '{name}'") from e

    # pylint: disable=unused-argument
    def __init__(self, name: str | None = None, wait_start_time: float = 0.0, **kwargs):
        """Initialize an `Agent` instance with the provided arguments.

        Args:
            name (optional): The name of the agent. If is not provided, the name of the class will 
                be used. Defaults to `None`.
            wait_start_time (optional): Seconds to wait after calling `on_test_start` before 
                continuing. Defaults to `0.0`.
            kwargs (optional): Additional parameters.
        """

        self.name = self.__class__.__name__ if name is None else name
        """The name of the agent."""

        self.wait_start_time: float = wait_start_time
        """Time to wait after calling `on_test_start` before continuing."""

    def set_options(self, **kwargs):
        """Set options for the agent.

        This method should be called before passing the agent to the engine.

        Args:
            kwargs: Additional keyword arguments.

        Raises:
            AgentError: If some error occurred at the agent side. In this case the method 
                `stop_execution` is called.
        """

    def get_supported_paths(self, protocol: str) -> list[list[str]]:
        """Get the all the paths supported by the current agent for the given protocol.

        This method should be called from the engine before starting a run.

        Args:
            protocol: The name of the protocol to be used.

        Returns:
            list[list[str]]|bool: The list of paths supported by the current agent. Each element 
                of the main list is a list of message names that compose the path. If there are no specific paths supported, an empty list should be returned.

        Raises:
            AgentError: If some error occurred at the agent side. In this case the method 
                `stop_execution` is called.
        """

        return []

    def on_test_start(self, ctx: ExecutionContext):
        """Called right before the start of a test case.

        Raises:
            AgentError: If some error occurred at the agent side. In this case the method 
                `stop_execution` is called.
        """

    def on_test_end(self):
        """Called right after the end of a test case.

        Raises:
             AgentError: If some error occurred at the agent side. In this case the method 
                `stop_execution` is called.
        """

    def get_data(self) -> list[tuple[str, bytes]]:
        """Get any data during a test case.

        Returns:
            list[tuple[str, bytes]]: A list of tuples containing the name of the data and its 
                content.

        Raises:
            AgentError: If some error occurred at the agent side. In this case the method 
                `stop_execution` is called.
        """

        return []

    def skip_epoch(self, ctx: ExecutionContext) -> bool:
        """Should the current epoch be skipped.

        This method should be called before `on_test_start`.

        Raises:
            AgentError: If some error occurred at the agent side. In this case the method 
                `stop_execution` is called.
        """

        return False

    def redo_test(self) -> bool:
        """Should the current test be re-performed.

        Raises:
            AgentError: If some error occurred at the agent side. In this case the method 
                `stop_execution` is called.
        """

        return False

    def fault_detected(self) -> bool:
        """Check if a fault was detected during the current test case.

        Raises:
            AgentError: If some error occurred at the agent side. In this case the method 
                `stop_execution` is called.
        """

        return False

    def on_fault(self):
        """Called when a fault was detected by at least one agent during the current test case.

        Raises:
            AgentError: If some error occurred at the agent side. In this case the method 
                `stop_execution` is called.
        """

    def on_shutdown(self):
        """Called when the `Agent` is shutting down.

        This is typically done in the following situations:
        - At the end of a run.
        - In case of a single epoch, at the end of the epoch.
        - In case of a single test case, at the end of the test case.

        Raises:
            AgentError: If some error occurred at the agent side. In this case the agent should be 
                shutted down with the force.
        """

    def stop_execution(self) -> bool:
        """Check if the execution of the fuzzer should be stopped.

        This should return `True` if an unrecoverable error occurs.
        """

        return False

    ############################################################################################
    ########################               Publisher Methods             #######################
    ############################################################################################

    def start(self, pub_id: int):
        """Set the `Publisher` specified to a running state where it can send/receive new data.

        Change state such that `receive`/`receive` will work. For TCP this could be
        connecting to a remote host, for a file it might be opening the file handle.

        Args:
            pub_id: The id of the publisher.

        Raises:
            AgentError: If some error occurred at the agent side.
        """

        return

    def stop(self, pub_id: int):
        """Set the `Publisher` specified to a stopped state where it can't send/receive new data.

        Change state such that `send`/`receive` will not work. For TCP this could
        be closing a connection, for a file it might be closing the file handle.

        Args:
            pub_id: The id of the publisher.

        Raises:
            AgentError: If some error occurred at the agent side. In this case the publisher should 
                be stopped with the force.
        """

        return

    def send(self, pub_id: int, data: bytes):
        """Send some data to the `Publisher` specified.

        Args:
            pub_id: The id of the publisher.
            data: The data to be sent.

        Raises:
            AgentError: If some error occurred at the agent side.
        """

        return

    def receive(self, pub_id: int) -> bytes:
        """Receive some data from the `Publisher` specified.

        Args:
            pub_id: The id of the publisher.

        Returns:
            bytes: The received data.

        Raises:
            AgentError: If some error occurred at the agent side.
        """

        return b""

    def data_available(self, pub_id: int) -> bool:
        """Check if there is any data available for reading from the `Publisher` specified.

        Args:
            pub_id: The id of the publisher.

        Returns:
            bool: `True` if there is data available, `False` otherwise.

        Raises:
            AgentError: If some error occurred at the agent side.
        """

        return False


class AgentMultiplexer:
    """Manages communication with one or more agents."""

    def __init__(self):
        """Initialize an instance of `AgentMultiplexer`."""

        self._agents: list[Agent] = []

    def add_agent(self, agent: Agent):
        """Add a new agent to the multiplexer.

        Args:
            agent: The new agent to be added.
        """

        self._agents.append(agent)

    def _log_for(self, agent: Agent) -> logging.Logger:
        """Get the logger for a specific agent.

        Args:
            agent: The agent for which the logger is needed.

        Returns:
            logging.Logger: The logger for the specified agent.
        """

        return logging.getLogger(agent.name)

    def _handle_error(self, agent: Agent, e: AgentError):
        """Handle errors raised by agents.

        This method logs the error and checks if the execution should be stopped.

        Args:
            agent: The agent that raised the error.
            e: The error that was raised.

        Raises:
            AgentError: If the agent signaled an unrecoverable error.
        """

        self._log_for(agent).warning("%s", str(e))
        if agent.stop_execution():
            self._log_for(agent).critical("Unrecoverable error: %s", str(e))
            raise AgentError(f"Agent {agent.name}: {str(e)}") from e

    def get_supported_paths(self, protocol: str) -> list[list[str]]:
        """Executes `get_supported_paths` for each agent in the multiplexer.

        Args:
            protocol: The name of the protocol to be used.

        Returns:
            list[list[str]]|bool: The list of all the paths supported the current agents. Each 
            element of the main list is a list of message names that compose the path. If there are 
            no specific paths supported, an empty list should be returned.

        Raises:
            AgentError: If any of the agents wants to stop the execution.
        """

        paths = []
        for agent in self._agents:
            try:
                res = agent.get_supported_paths(protocol)
                if isinstance(res, list):
                    paths.extend(res)
            except AgentError as e:
                self._handle_error(agent, e)

        return res

    def on_test_start(self, ctx: ExecutionContext):
        """Executes `on_test_start` for each agent in the multiplexer.

        Raises:
            AgentError: If any of the agents wants to stop the execution.
        """

        for agent in self._agents:
            try:
                agent.on_test_start(ctx)
                time.sleep(agent.wait_start_time)
            except AgentError as e:
                self._handle_error(agent, e)

    def on_test_end(self):
        """Executes `on_test_end` for each agent in the multiplexer.

        Note: the order of agents in which `on_test_end` is called is the inverse of the order in 
        which `on_test_start` is called.

        Raises:
            AgentError: If any of the agents wants to stop the execution.
        """

        for agent in self._agents[::-1]:
            try:
                agent.on_test_end()
            except AgentError as e:
                self._handle_error(agent, e)

    def get_data(self) -> list[tuple[str, bytes]]:
        """Executes `get_data` for each agent in the multiplexer.

        Returns:
            list[tuple[str, bytes]]: All the data returned by the agents.

        Raises:
            AgentError: If any of the agents wants to stop the execution.
        """

        data = []
        for agent in self._agents:
            try:
                new_data = agent.get_data()
                if len(new_data) > 0:
                    for i, record in enumerate(new_data):
                        new_data[i] = (agent.name + "." + record[0], record[1])
                data += new_data
            except AgentError as e:
                self._handle_error(agent, e)

        return data

    def skip_epoch(self, ctx: ExecutionContext) -> bool:
        """Executes `skip_epoch` for each agent in the multiplexer.

        Returns:
            bool: `True` if at least one agent signaled to skip the epoch.

        Raises:
            AgentError: If any of the agents wants to stop the execution.
        """

        skip = False
        for agent in self._agents:
            try:
                new_skip = agent.skip_epoch(ctx)
                self._log_for(agent).debug('Skip = %s', 'yes' if new_skip else 'no')
                skip = skip or new_skip
            except AgentError as e:
                self._handle_error(agent, e)

        return skip

    def redo_test(self) -> bool:
        """Executes `redo_test` for each agent in the multiplexer.

        Returns:
            bool: `True` if at least one agent signaled to redo the test.

        Raises:
            AgentError: If any of the agents wants to stop the execution.
        """

        redo = False
        for agent in self._agents:
            try:
                new_redo = agent.redo_test()
                self._log_for(agent).debug('Redo = %s', 'yes' if new_redo else 'no')
                redo = redo or new_redo
            except AgentError as e:
                self._handle_error(agent, e)

        return redo

    def fault_detected(self) -> bool:
        """Executes `fault_detected` for each agent in the multiplexer.

        Returns:
            bool: `True` if at least one agent detected a fault.

        Raises:
            AgentError: If any of the agents wants to stop the execution.
        """

        fault = False
        for agent in self._agents:
            try:
                new_fault = agent.fault_detected()
                self._log_for(agent).debug('Fault = %s', 'yes' if new_fault else 'no')
                fault = fault or new_fault
            except AgentError as e:
                self._handle_error(agent, e)

        return fault

    def on_fault(self):
        """Executes `on_fault` for each agent in the multiplexer.

        Raises:
            AgentError: If any of the agents wants to stop the execution.
        """

        for agent in self._agents:
            try:
                agent.on_fault()
            except AgentError as e:
                self._handle_error(agent, e)

    def on_shutdown(self):
        """Executes `on_shutdown` for each agent in the multiplexer."""

        for agent in self._agents:
            try:
                agent.on_shutdown()
            except AgentError as e:
                self._log_for(agent).warning("%s", str(e))


# so that all agent classes are created
from .agents import *
