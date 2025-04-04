import json
from typing import override

import grpc
from google.protobuf.any_pb2 import Any
from google.protobuf.wrappers_pb2 import StringValue, BoolValue, BytesValue, Int32Value, UInt32Value, Int64Value, UInt64Value

from ...agent import Agent, ExecutionContext
from .serializers import ExecutionContextSerializer
from .generated import agent_pb2
from .generated.agent_pb2_grpc import AgentServiceStub

from ...utils.errs import *


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
                - `'ip'`: A string representing the IP address of the gRPC server.
                - `'port'`: A number representing the port the gRPC server is listening on.
        """

        super().__init__(name, wait_start_time, **kwargs)

        self._ip: str = kwargs['ip']
        self._port: int = kwargs['port']

        self._channel = grpc.insecure_channel(
            f"{self._ip}:{self._port}",
            options=[('grpc.max_receive_message_length', -1), ('grpc.max_send_message_length', -1)]
        )
        self._stub = AgentServiceStub(self._channel)

    @property
    def ip(self) -> str:
        """The IP address of the gRPC server."""

        return self._ip

    @property
    def port(self) -> int:
        """The port the gRPC server is listening on."""

        return self._port

    @override
    def set_options(self, **kwargs):
        # pylint: disable=no-member
        options = [agent_pb2.RequestMessage.Options.Option(
            name=k, value=json.dumps(v)) for k, v in kwargs.items()]

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
    def reset(self):
        try:
            # pylint: disable=no-member
            response = self._stub.resetAgent(agent_pb2.RequestMessage())
        except grpc.RpcError as e:
            raise AgentError(f"gRPC error: {e}") from e

        # pylint: disable=no-member
        if response.status == agent_pb2.ResponseMessage.Status.ERROR:
            if not response.HasField('error'):
                raise AgentError("Unknown error")

            raise AgentError(response.error)

    @override
    def get_supported_paths(self, protocol: str) -> list[list[dict[str, str | bool]]]:
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
            p = []
            for message in path.messages:
                msg = {}
                key: str
                any_value: Any
                for key, any_value in message.message.items():
                    if any_value.Is(StringValue.DESCRIPTOR):
                        value = StringValue()
                    elif any_value.Is(BoolValue.DESCRIPTOR):
                        value = BoolValue()
                    elif any_value.Is(BytesValue.DESCRIPTOR):
                        value = BytesValue()
                    elif any_value.Is(UInt32Value.DESCRIPTOR):
                        value = UInt32Value()
                    elif any_value.Is(UInt64Value.DESCRIPTOR):
                        value = UInt64Value()
                    elif any_value.Is(Int32Value.DESCRIPTOR):
                        value = Int32Value()
                    elif any_value.Is(Int64Value.DESCRIPTOR):
                        value = Int64Value()
                    else:
                        raise AgentError(f"Unknown value received: {any_value.value}")
                    any_value.Unpack(value)
                    msg[key] = value.value
                p.append(msg)
            res.append(p)
        return res

    @override
    def on_epoch_start(self, ctx: ExecutionContext):
        data = ExecutionContextSerializer.serialize(ctx)

        try:
            # pylint: disable=no-member
            response = self._stub.onEpochStart(
                agent_pb2.RequestMessage(ctx=data))
        except grpc.RpcError as e:
            raise AgentError(f"gRPC error: {e}") from e

        # pylint: disable=no-member
        if response.status == agent_pb2.ResponseMessage.Status.ERROR:
            if not response.HasField('error'):
                raise AgentError("Unknown error")

            raise AgentError(response.error)

    @override
    def on_epoch_end(self):
        try:
            # pylint: disable=no-member
            response = self._stub.onEpochEnd(agent_pb2.RequestMessage())
        except grpc.RpcError as e:
            raise AgentError(f"gRPC error: {e}") from e

        # pylint: disable=no-member
        if response.status == agent_pb2.ResponseMessage.Status.ERROR:
            if not response.HasField('error'):
                raise AgentError("Unknown error")

            raise AgentError(response.error)

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
            res = []
            for response in self._stub.getData(agent_pb2.RequestMessage()):
                if response.status == agent_pb2.ResponseMessage.Status.ERROR:
                    if not response.HasField('error'):
                        raise AgentError("Unknown error")
                    raise AgentError(response.error)

                if not response.HasField('data') or not response.data.HasField('test_data'):
                    raise AgentError("Unknown result")

                record = response.data.test_data
                res.append((record.name, record.content))
        except grpc.RpcError as e:
            raise AgentError(f"gRPC error: {e}") from e

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
    def on_redo(self):
        try:
            # pylint: disable=no-member
            response = self._stub.onRedo(agent_pb2.RequestMessage())
        except grpc.RpcError as e:
            raise AgentError(f"gRPC error: {e}") from e

        # pylint: disable=no-member
        if response.status == agent_pb2.ResponseMessage.Status.ERROR:
            if not response.HasField('error'):
                raise AgentError("Unknown error")

            raise AgentError(response.error)

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

    def __eq__(self, value):
        return isinstance(value, GrpcClientAgent) \
            and self.name == value.name \
            and self.ip == value.ip \
            and self.port == value.port
