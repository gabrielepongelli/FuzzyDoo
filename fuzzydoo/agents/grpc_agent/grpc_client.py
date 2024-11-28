import pickle
from typing import override

import grpc

from ...agent import Agent, AgentError, ExecutionContext
from .serializers import ExecutionContextSerializer
from .generated import agent_pb2
from .generated.agent_pb2_grpc import AgentServiceStub


class GrpcClientAgent(Agent):
    """An agent for interacting with a remote gRPC server."""

    def __init__(self, name: str | None = None, wait_start_time: float = 0.0, **kwargs):
        """Initialize an `GrpcClientAgent` instance with the provided arguments.

        Args:
            name (optional): The name of the agent. If is not provided, the name of the class will 
                be used. Defaults to `None`.
            wait_start_time (optional): Seconds to wait after calling `on_test_start` before 
                continuing. Defaults to `0.0`.
            kwargs: Additional parameters. It must contain the following keys:
                'ip': A string representing the IP address of the gRPC server.
                'port': A number representing the port the gRPC server is listening on.
        """

        super().__init__(name, wait_start_time, **kwargs)

        self._channel = grpc.insecure_channel(
            f"{kwargs['ip']}:{kwargs['port']}")
        self._stub = AgentServiceStub(self._channel)

    @override
    def set_options(self, **kwargs):
        # pylint: disable=no-member
        options = [agent_pb2.RequestMessage.Options.Option(
            name=k, value=pickle.dumps(v)) for k, v in kwargs.items()]

        data = agent_pb2.RequestMessage.Options()
        data.records.extend(options)

        try:
            response = self._stub.setOptions(
                agent_pb2.RequestMessage(options=data))
        except grpc.RpcError as e:
            raise AgentError(f"gRPC error: {e}") from e

        # pylint: disable=no-member
        if response.status == agent_pb2.ResponseMessage.Status.ERROR:
            if not response.HasField('error'):
                raise AgentError("Unknown error")

            raise AgentError(response.error)

    @override
    def get_supported_paths(self, protocol: str) -> list[list[str]]:
        try:
            # pylint: disable=no-member
            response = self._stub.getSupportedPaths(
                agent_pb2.RequestMessage(protocol=protocol))
        except grpc.RpcError as e:
            raise AgentError(f"gRPC error: {e}") from e

        # pylint: disable=no-member
        if response.status == agent_pb2.ResponseMessage.Status.ERROR:
            if not response.HasField('error'):
                raise AgentError("Unknown error")

            raise AgentError(response.error)

        if not response.HasField('data') or not response.data.HasField('protocol_paths'):
            return AgentError("Unknown result")

        res = []
        for path in response.data.protocol_paths.paths:
            res.append([msg for msg in path.messages])
        return res

    @override
    def on_test_start(self, ctx: ExecutionContext):
        data = ExecutionContextSerializer.serialize(ctx)

        try:
            # pylint: disable=no-member
            response = self._stub.onTestStart(
                agent_pb2.RequestMessage(ctx=data))
        except grpc.RpcError as e:
            raise AgentError(f"gRPC error: {e}") from e

        # pylint: disable=no-member
        if response.status == agent_pb2.ResponseMessage.Status.ERROR:
            if not response.HasField('error'):
                raise AgentError("Unknown error")

            raise AgentError(response.error)

    @override
    def on_test_end(self):
        try:
            # pylint: disable=no-member
            response = self._stub.onTestEnd(agent_pb2.RequestMessage())
        except grpc.RpcError as e:
            raise AgentError(f"gRPC error: {e}") from e

        # pylint: disable=no-member
        if response.status == agent_pb2.ResponseMessage.Status.ERROR:
            if not response.HasField('error'):
                raise AgentError("Unknown error")

            raise AgentError(response.error)

    @override
    def get_data(self) -> list[tuple[str, bytes]]:
        try:
            # pylint: disable=no-member
            response = self._stub.getData(agent_pb2.RequestMessage())
        except grpc.RpcError as e:
            raise AgentError(f"gRPC error: {e}") from e

        # pylint: disable=no-member
        if response.status == agent_pb2.ResponseMessage.Status.ERROR:
            if not response.HasField('error'):
                raise AgentError("Unknown error")

            raise AgentError(response.error)

        if not response.HasField('data') or not response.data.HasField('test_data'):
            return AgentError("Unknown result")

        res = []
        for record in response.data.test_data.records:
            res.append((record.name, record.content))
        return res

    @override
    def skip_epoch(self, ctx: ExecutionContext) -> bool:
        data = ExecutionContextSerializer.serialize(ctx)

        try:
            # pylint: disable=no-member
            response = self._stub.skipEpoch(
                agent_pb2.RequestMessage(ctx=data))
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

    @override
    def redo_test(self) -> bool:
        try:
            # pylint: disable=no-member
            response = self._stub.redoTest(agent_pb2.RequestMessage())
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

    @override
    def fault_detected(self) -> bool:
        try:
            # pylint: disable=no-member
            response = self._stub.faultDetected(agent_pb2.RequestMessage())
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

    @override
    def on_fault(self):
        try:
            # pylint: disable=no-member
            response = self._stub.onFault(agent_pb2.RequestMessage())
        except grpc.RpcError as e:
            raise AgentError(f"gRPC error: {e}") from e

        # pylint: disable=no-member
        if response.status == agent_pb2.ResponseMessage.Status.ERROR:
            if not response.HasField('error'):
                raise AgentError("Unknown error")

            raise AgentError(response.error)

    @override
    def on_shutdown(self):
        try:
            # pylint: disable=no-member
            response = self._stub.onShutdown(agent_pb2.RequestMessage())
        except grpc.RpcError as e:
            self._channel.close()
            raise AgentError(f"gRPC error: {e}") from e

        self._channel.close()

        # pylint: disable=no-member
        if response.status == agent_pb2.ResponseMessage.Status.ERROR:
            if not response.HasField('error'):
                raise AgentError("Unknown error")

            raise AgentError(response.error)

    @override
    def stop_execution(self) -> bool:
        """Check if the execution should be stopped.

        If any error is encountered, the result will be `True`.
        """

        try:
            # pylint: disable=no-member
            response = self._stub.stopExecution(agent_pb2.RequestMessage())
        except grpc.RpcError:
            return True

        # pylint: disable=no-member
        if response.status == agent_pb2.ResponseMessage.Status.ERROR:
            return True

        if not response.HasField('flag'):
            return True

        return response.flag

    ############################################################################################
    ########################               Publisher Methods             #######################
    ############################################################################################

    @override
    def start(self, pub_id: int):
        # pylint: disable=no-member
        data = agent_pb2.PublisherData(id=pub_id)

        try:
            # pylint: disable=no-member
            response = self._stub.startPublisher(
                agent_pb2.RequestMessage(publisher_data=data))
        except grpc.RpcError as e:
            raise AgentError(f"gRPC error: {e}") from e

        # pylint: disable=no-member
        if response.status == agent_pb2.ResponseMessage.Status.ERROR:
            if not response.HasField('error'):
                raise AgentError("Unknown error")

            raise AgentError(response.error)

    @override
    def stop(self, pub_id: int):
        # pylint: disable=no-member
        data = agent_pb2.PublisherData(id=pub_id)

        try:
            # pylint: disable=no-member
            response = self._stub.stopPublisher(
                agent_pb2.RequestMessage(publisher_data=data))
        except grpc.RpcError as e:
            raise AgentError(f"gRPC error: {e}") from e

        # pylint: disable=no-member
        if response.status == agent_pb2.ResponseMessage.Status.ERROR:
            if not response.HasField('error'):
                raise AgentError("Unknown error")

            raise AgentError(response.error)

    @override
    def send(self, pub_id: int, data: bytes):
        # pylint: disable=no-member
        data = agent_pb2.PublisherData(id=pub_id, data=data)

        try:
            # pylint: disable=no-member
            response = self._stub.sendToPublisher(
                agent_pb2.RequestMessage(publisher_data=data))
        except grpc.RpcError as e:
            raise AgentError(f"gRPC error: {e}") from e

        # pylint: disable=no-member
        if response.status == agent_pb2.ResponseMessage.Status.ERROR:
            if not response.HasField('error'):
                raise AgentError("Unknown error")

            raise AgentError(response.error)

    @override
    def receive(self, pub_id: int) -> bytes:
        # pylint: disable=no-member
        data = agent_pb2.PublisherData(id=pub_id)

        try:
            # pylint: disable=no-member
            response = self._stub.receiveFromPublisher(
                agent_pb2.RequestMessage(publisher_data=data))
        except grpc.RpcError as e:
            raise AgentError(f"gRPC error: {e}") from e

        # pylint: disable=no-member
        if response.status == agent_pb2.ResponseMessage.Status.ERROR:
            if not response.HasField('error'):
                raise AgentError("Unknown error")

            raise AgentError(response.error)

        if not response.HasField('data'):
            return AgentError("Unknown result")

        if response.data.HasField('raw_data'):
            return response.data.raw_data

        return b""

    @override
    def data_available(self, pub_id: int) -> bool:
        # pylint: disable=no-member
        data = agent_pb2.PublisherData(id=pub_id)

        try:
            # pylint: disable=no-member
            response = self._stub.dataAvailableToPublisher(
                agent_pb2.RequestMessage(publisher_data=data))
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
