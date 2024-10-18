import pickle
from concurrent.futures import ThreadPoolExecutor

import grpc

from ...agent import Agent, AgentError
from .generated import agent_pb2, agent_pb2_grpc


class GrpcServerAgent(Agent, agent_pb2_grpc.AgentServiceServicer):
    """A gRPC server representing a remote agent.

    Attributes:
        server: The gRPC server instance. This can be used inside a method of the `Agent` class to 
            stop the execution of the server with `server.stop()`.
    """

    def __init__(self, name: str | None = None, /, **kwargs):
        """Initialize an `GrpcServerAgent` instance with the provided arguments.

        Args:
            name (optional): The name of the agent. If is not provided, the name of the class will 
                be used. Defaults to `None`.
            kwargs: Additional parameters. It must contain the following keys:
                'address': A string representing the IP address on which the gRPC server should 
                    listen.
                'port': A number representing the port the gRPC server should listen on.
        """

        super(agent_pb2_grpc.AgentServiceServicer).__init__()
        super(Agent).__init__(name, **kwargs)

        self._address: str = kwargs['address']
        self._port: int = kwargs['port']
        self.server = grpc.server(ThreadPoolExecutor(max_workers=1))

        agent_pb2_grpc.add_AgentServiceServicer_to_server(
            self, self.server)

        self.server.add_insecure_port(f"{self._address}:{self._port}")

    @property
    def address(self) -> str:
        """The address of the gRPC server."""

        return self._address

    @property
    def port(self) -> int:
        """The port of the gRPC server."""

        return self._port

    def serve(self):
        """Start the gRPC server and handle incoming requests.

        This method starts the gRPC server and waits for incoming requests. It also handles 
        KeyboardInterrupt exceptions by calling the `on_shutdown` method and stopping the server 
        gracefully.
        """

        self.server.start()

        try:
            self.server.wait_for_termination()
        except KeyboardInterrupt:
            try:
                self.on_shutdown()
            except AgentError:
                pass

            self.server.stop(grace=0)

    def setOptions(self, request, context):
        options = {}
        for opt in request.options:
            options[opt.name] = pickle.loads(opt.value)

        try:
            self.set_options(**options)
        except AgentError as e:
            # pylint: disable=no-member
            return agent_pb2.ResponseMessage(
                status=agent_pb2.ResponseMessage.Status.ERROR,
                error=str(e))

        # pylint: disable=no-member
        return agent_pb2.ResponseMessage(status=agent_pb2.ResponseMessage.Status.OK)

    def onTestStart(self, request, context):
        try:
            self.on_test_start(request.path)
        except AgentError as e:
            # pylint: disable=no-member
            return agent_pb2.ResponseMessage(
                status=agent_pb2.ResponseMessage.Status.ERROR,
                error=str(e))

        # pylint: disable=no-member
        return agent_pb2.ResponseMessage(status=agent_pb2.ResponseMessage.Status.OK)

    def onTestEnd(self, request, context):
        try:
            self.on_test_end()
        except AgentError as e:
            # pylint: disable=no-member
            return agent_pb2.ResponseMessage(
                status=agent_pb2.ResponseMessage.Status.ERROR,
                error=str(e))

        # pylint: disable=no-member
        return agent_pb2.ResponseMessage(status=agent_pb2.ResponseMessage.Status.OK)

    def getData(self, request, context):
        try:
            res = self.get_data()
        except AgentError as e:
            # pylint: disable=no-member
            return agent_pb2.ResponseMessage(
                status=agent_pb2.ResponseMessage.Status.ERROR,
                error=str(e))

        # pylint: disable=no-member
        records = [agent_pb2.ResponseMessage.TestData.TestDataRecord(
            name=r[0], content=r[1]) for r in res]
        data = agent_pb2.ResponseMessage.TestData()
        data.records.extend(records)

        # pylint: disable=no-member
        return agent_pb2.ResponseMessage(status=agent_pb2.ResponseMessage.Status.OK, data=data)

    def redoTest(self, request, context):
        try:
            res = self.redo_test()
        except AgentError as e:
            # pylint: disable=no-member
            return agent_pb2.ResponseMessage(
                status=agent_pb2.ResponseMessage.Status.ERROR,
                error=str(e))

        # pylint: disable=no-member
        return agent_pb2.ResponseMessage(status=agent_pb2.ResponseMessage.Status.OK, flag=res)

    def faultDetected(self, request, context):
        try:
            res = self.fault_detected()
        except AgentError as e:
            # pylint: disable=no-member
            return agent_pb2.ResponseMessage(
                status=agent_pb2.ResponseMessage.Status.ERROR,
                error=str(e))

        # pylint: disable=no-member
        return agent_pb2.ResponseMessage(status=agent_pb2.ResponseMessage.Status.OK, flag=res)

    def onFault(self, request, context):
        try:
            self.on_fault()
        except AgentError as e:
            # pylint: disable=no-member
            return agent_pb2.ResponseMessage(
                status=agent_pb2.ResponseMessage.Status.ERROR,
                error=str(e))

        # pylint: disable=no-member
        return agent_pb2.ResponseMessage(status=agent_pb2.ResponseMessage.Status.OK)

    def onShutdown(self, request, context):
        try:
            self.on_shutdown()
        except AgentError as e:
            # pylint: disable=no-member
            return agent_pb2.ResponseMessage(
                status=agent_pb2.ResponseMessage.Status.ERROR,
                error=str(e))

        # pylint: disable=no-member
        return agent_pb2.ResponseMessage(status=agent_pb2.ResponseMessage.Status.OK)

    def stopExecution(self, request, context):
        try:
            res = self.stop_execution()
        except AgentError as e:
            # pylint: disable=no-member
            response = agent_pb2.ResponseMessage(
                status=agent_pb2.ResponseMessage.Status.ERROR,
                error=str(e))
        else:
            response = agent_pb2.ResponseMessage(  # pylint: disable=no-member
                status=agent_pb2.ResponseMessage.Status.OK, flag=res)  # pylint: disable=no-member

        # wait for the completion of this method for maximum 10 seconds
        self.server.stop(10)

        return response
