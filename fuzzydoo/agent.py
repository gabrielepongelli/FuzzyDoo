import logging

from .utils.errs import FuzzyDooError


class AgentError(FuzzyDooError):
    """Generic error for the `Agent` interface."""


class Agent:
    """A remote or local agent.

    Agents are independent programs running somewhere (in the same machine or not).

    To execute some action, just override the appropriate method.
    """

    # pylint: disable=unused-argument
    def __init__(self, name: str | None = None, /, **kwargs):
        """Initialize an `Agent` instance with the provided arguments.

        Args:
            name (optional): The name of the agent. If is not provided, the name of the class will 
                be used. Defaults to `None`.
            kwargs (optional): Additional parameters.
        """

        self._name = self.__class__.__name__ if name is None else name

    @property
    def name(self) -> str:
        """The name of the agent."""

        return self._name

    def set_options(self, **kwargs):
        """Set options for the agent.

        This method should be called before passing the agent to the engine.

        Args:
            kwargs: Additional keyword arguments.

        Raises:
            AgentError: If some error occurred at the agent side. In this case the method 
                `stop_execution` is called.
        """

    def on_test_start(self, path: str):
        """Called right before the start of a test case.

        Args:
            path: The path of the test being run.

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

    def redo_test(self) -> bool:
        """Should the current test be re-performed.

        Raises:
            AgentError: If some error occurred at the agent side. In this case the method 
                `stop_execution` is called.
        """

        return False

    def fault_detected(self) -> bool:
        """Check if a fault was detected.

        Raises:
            AgentError: If some error occurred at the agent side. In this case the method 
                `stop_execution` is called.
        """

        return False

    def on_fault(self):
        """Called when a fault was detected.

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


class AgentMultiplexer:
    """Manages communication with one or more agents."""

    def __init__(self):
        """Initialize an instance of `AgentMultiplexer`."""

        self._agents: list[Agent] = []
        self._logger = logging.getLogger('agent')

    def add_agent(self, agent: Agent):
        """Add a new agent to the multiplexer.

        Args:
            agent: The new agent to be added.
        """

        self._agents.append(agent)
        self._logger.info('Added agent %s', agent.name)

    def _handle_error(self, agent: Agent, e: AgentError):
        """Handle errors raised by agents.

        This method logs the error and checks if the execution should be stopped.

        Args:
            agent: The agent that raised the error.
            e: The error that was raised.

        Raises:
            AgentError: If the agent signaled an unrecoverable error.
        """

        self._logger.warning(
            "Error from agent %s: %s", agent.name, str(e))
        if agent.stop_execution():
            self._logger.error(
                "Agent %s signaled an unrecoverable error", agent.name)
            raise AgentError(f"Agent {agent.name}: {str(e)}") from e

    def on_test_start(self, path: str):
        """Executes `on_test_start` for each agent in the multiplexer.

        Args:
            path: The path of the test being run.

        Raises:
            AgentError: If any of the agents wants to stop the execution.
        """

        self._logger.debug('On test start')

        for agent in self._agents:
            try:
                agent.on_test_start(path)
            except AgentError as e:
                self._handle_error(agent, e)

    def on_test_end(self):
        """Executes `on_test_end` for each agent in the multiplexer.

        Raises:
            AgentError: If any of the agents wants to stop the execution.
        """

        self._logger.debug('On test end')

        for agent in self._agents:
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

        self._logger.debug('Get data')

        data = []
        for agent in self._agents:
            try:
                data += agent.get_data()
            except AgentError as e:
                self._handle_error(agent, e)

        return data

    def redo_test(self) -> bool:
        """Executes `redo_test` for each agent in the multiplexer.

        Returns:
            bool: `True` if at least one agent signaled to redo the test.

        Raises:
            AgentError: If any of the agents wants to stop the execution.
        """

        self._logger.debug('Redo test')

        redo = False
        for agent in self._agents:
            try:
                redo = redo or agent.get_data()
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

        self._logger.debug('Fault detected')

        fault = False
        for agent in self._agents:
            try:
                fault = fault or agent.get_data()
            except AgentError as e:
                self._handle_error(agent, e)

        return fault

    def on_fault(self):
        """Executes `on_fault` for each agent in the multiplexer.

        Raises:
            AgentError: If any of the agents wants to stop the execution.
        """

        self._logger.debug('On fault')

        for agent in self._agents:
            try:
                agent.on_fault()
            except AgentError as e:
                self._handle_error(agent, e)

    def on_shutdown(self):
        """Executes `on_shutdown` for each agent in the multiplexer."""

        self._logger.debug('On shutdown')

        for agent in self._agents:
            try:
                agent.on_shutdown()
            except AgentError as e:
                self._logger.warning(
                    "Error from agent %s: %s", agent.name, str(e))
