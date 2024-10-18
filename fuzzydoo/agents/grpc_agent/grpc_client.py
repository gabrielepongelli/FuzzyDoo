import pickle

import grpc

from ...agent import Agent, AgentError
from .generated import agent_pb2
from .generated.agent_pb2_grpc import AgentServiceStub


class GrpcClientAgent(Agent):
    """An agent for interacting with a remote gRPC server."""

    def __init__(self, name: str | None = None, /, **kwargs):
        """Initialize an `GrpcClientAgent` instance with the provided arguments.

        Args:
            name (optional): The name of the agent. If is not provided, the name of the class will 
                be used. Defaults to `None`.
            kwargs: Additional parameters. It must contain the following keys:
                'address': A string representing the IP address of the gRPC server.
                'port': A number representing the port the gRPC server is listening on.
        """

        super().__init__(name, **kwargs)

        self._channel = grpc.insecure_channel(
            f"{kwargs['address']}:{kwargs['port']}")
        self._stub = AgentServiceStub(self._channel)

    def set_options(self, **kwargs):
        # pylint: disable=no-member
        options = [agent_pb2.OptionsMessage.Option(
            name=k, value=pickle.dumps(v)) for k, v in kwargs.items()]

        msg = agent_pb2.OptionsMessage()
        msg.options.extend(options)

        try:
            response = self._stub.setOptions(msg)
        except grpc.RpcError as e:
            raise AgentError(f"gRPC error: {e}") from e

        # pylint: disable=no-member
        if response.status == agent_pb2.ResponseMessage.Status.ERROR:
            if not response.HasField('error'):
                raise AgentError("Unknown error")

            raise AgentError(response.error)

    def on_test_start(self, path: str):
        # pylint: disable=no-member
        info = agent_pb2.TestInfoMessage(path=path)

        try:
            response = self._stub.onTestStart(info)
        except grpc.RpcError as e:
            raise AgentError(f"gRPC error: {e}") from e

        # pylint: disable=no-member
        if response.status == agent_pb2.ResponseMessage.Status.ERROR:
            if not response.HasField('error'):
                raise AgentError("Unknown error")

            raise AgentError(response.error)

    def on_test_end(self):
        try:
            # pylint: disable=no-member
            response = self._stub.onTestEnd(agent_pb2.EmptyMessage())
        except grpc.RpcError as e:
            raise AgentError(f"gRPC error: {e}") from e

        # pylint: disable=no-member
        if response.status == agent_pb2.ResponseMessage.Status.ERROR:
            if not response.HasField('error'):
                raise AgentError("Unknown error")

            raise AgentError(response.error)

    def get_data(self) -> list[tuple[str, bytes]]:
        try:
            # pylint: disable=no-member
            response = self._stub.getData(agent_pb2.EmptyMessage())
        except grpc.RpcError as e:
            raise AgentError(f"gRPC error: {e}") from e

        # pylint: disable=no-member
        if response.status == agent_pb2.ResponseMessage.Status.ERROR:
            if not response.HasField('error'):
                raise AgentError("Unknown error")

            raise AgentError(response.error)

        if not response.HasField('data'):
            return AgentError("Unknown result")

        res = []
        for record in response.data.records:
            res.append((record.name, record.content))
        return res

    def redo_test(self) -> bool:
        try:
            # pylint: disable=no-member
            response = self._stub.redoTest(agent_pb2.EmptyMessage())
        except grpc.RpcError as e:
            raise AgentError(f"gRPC error: {e}") from e

        # pylint: disable=no-member
        if response.status == agent_pb2.ResponseMessage.Status.ERROR:
            if not response.HasField('error'):
                raise AgentError("Unknown error")

            raise AgentError(response.error)

        if not response.HasField('flag'):
            return AgentError("Unknown result")

        return response.flag

    def fault_detected(self) -> bool:
        try:
            # pylint: disable=no-member
            response = self._stub.faultDetected(agent_pb2.EmptyMessage())
        except grpc.RpcError as e:
            raise AgentError(f"gRPC error: {e}") from e

        # pylint: disable=no-member
        if response.status == agent_pb2.ResponseMessage.Status.ERROR:
            if not response.HasField('error'):
                raise AgentError("Unknown error")

            raise AgentError(response.error)

        if not response.HasField('flag'):
            return AgentError("Unknown result")

        return response.flag

    def on_fault(self):
        try:
            # pylint: disable=no-member
            response = self._stub.onFault(agent_pb2.EmptyMessage())
        except grpc.RpcError as e:
            raise AgentError(f"gRPC error: {e}") from e

        # pylint: disable=no-member
        if response.status == agent_pb2.ResponseMessage.Status.ERROR:
            if not response.HasField('error'):
                raise AgentError("Unknown error")

            raise AgentError(response.error)

    def on_shutdown(self):
        try:
            # pylint: disable=no-member
            response = self._stub.onShutdown(agent_pb2.EmptyMessage())
        except grpc.RpcError as e:
            self._channel.close()
            raise AgentError(f"gRPC error: {e}") from e

        self._channel.close()

        # pylint: disable=no-member
        if response.status == agent_pb2.ResponseMessage.Status.ERROR:
            if not response.HasField('error'):
                raise AgentError("Unknown error")

            raise AgentError(response.error)

    def stop_execution(self) -> bool:
        """Check if the execution should be stopped.

        If any error is encountered, the result will be `True`.
        """

        try:
            # pylint: disable=no-member
            response = self._stub.stopExecution(agent_pb2.EmptyMessage())
        except grpc.RpcError:
            return True

        # pylint: disable=no-member
        if response.status == agent_pb2.ResponseMessage.Status.ERROR:
            return True

        if not response.HasField('flag'):
            return True

        return response.flag
