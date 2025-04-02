import logging
import json
from concurrent.futures import ThreadPoolExecutor

import grpc
from google.protobuf.any_pb2 import Any
from google.protobuf.wrappers_pb2 import StringValue, BoolValue, BytesValue, Int32Value, UInt32Value, Int64Value, UInt64Value

from ...agent import Agent
from .generated import agent_pb2, agent_pb2_grpc
from .serializers import ExecutionContextSerializer
from .serializer import DeserializationError

from ...utils.errs import *


class GrpcServerAgent(Agent, agent_pb2_grpc.AgentServiceServicer):
    """A gRPC server representing a remote agent."""

    server: grpc.Server
    """The gRPC server instance. This can be used inside a method of the `Agent` class to stop the 
    execution of the server with `server.stop()`."""

    def __init__(self, name: str | None = None, /, **kwargs):
        """Initialize an `GrpcServerAgent` instance with the provided arguments.

        Args:
            name (optional): The name of the agent. If is not provided, the name of the class will 
                be used. Defaults to `None`.
            kwargs: Additional parameters. It must contain the following keys:
                - `'address'`: A string representing the IP address on which the gRPC server should 
                        listen.
                - `'port'`: A number representing the port the gRPC server should listen on.
        """

        super().__init__(name)
        super(agent_pb2_grpc.AgentServiceServicer, self).__init__()

        logging.debug("address = %s", kwargs['address'])
        logging.debug("port = %s", kwargs['port'])

        self._address: str = kwargs['address']
        self._port: int = kwargs['port']
        self.server = grpc.server(
            ThreadPoolExecutor(max_workers=1),
            options=[('grpc.max_receive_message_length', -1), ('grpc.max_send_message_length', -1)]
        )
        agent_pb2_grpc.add_AgentServiceServicer_to_server(self, self.server)
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

        logging.info('Starting gRPC server at %s:%s', self._address, self._port)
        self.server.start()
        logging.info('Started')

        try:
            self.server.wait_for_termination()
        except KeyboardInterrupt:
            try:
                self.on_shutdown()
            except AgentError:
                pass

            logging.info('Shutting down')
            self.shutdown()

    def shutdown(self, timeout: float = 0):
        """Shut the gRPC server down.

        Args:
            timeout (optional): Timeout in seconds to wait for requests to complete before shutting 
                the server down. Default is `0`.
        """

        self.server.stop(grace=timeout)

    def setOptions(self, request, context):
        logging.debug('setOptions')

        if request.HasField('options'):
            options = {}
            try:
                for opt in request.options.records:
                    options[opt.name] = json.loads(opt.value)
                self.set_options(**options)
            except (AgentError, json.JSONDecodeError) as e:
                # pylint: disable=no-member
                return agent_pb2.ResponseMessage(
                    status=agent_pb2.ResponseMessage.Status.ERROR,
                    error=str(e))

        # pylint: disable=no-member
        return agent_pb2.ResponseMessage(status=agent_pb2.ResponseMessage.Status.OK)

    def resetAgent(self, request, context):
        logging.debug('resetAgent')

        try:
            self.reset()
        except AgentError as e:
            # pylint: disable=no-member
            return agent_pb2.ResponseMessage(
                status=agent_pb2.ResponseMessage.Status.ERROR,
                error=str(e))

        # pylint: disable=no-member
        return agent_pb2.ResponseMessage(status=agent_pb2.ResponseMessage.Status.OK)

    def getSupportedPaths(self, request, context):
        logging.debug('getSupportedPaths')

        if not request.HasField('protocol'):
            # pylint: disable=no-member
            return agent_pb2.ResponseMessage(
                status=agent_pb2.ResponseMessage.Status.ERROR,
                error="No protocol name available")

        try:
            res = self.get_supported_paths(request.protocol)
        except AgentError as e:
            # pylint: disable=no-member
            return agent_pb2.ResponseMessage(
                status=agent_pb2.ResponseMessage.Status.ERROR,
                error=str(e))

        # pylint: disable=no-member
        paths = agent_pb2.ResponseMessage.ProtocolPathsData()
        # pylint: disable=not-an-iterable
        for p in res:
            path = agent_pb2.ResponseMessage.ProtocolPathsData.ProtocolPath()
            for m in p:
                msg = agent_pb2.ResponseMessage.ProtocolPathsData.ProtocolMessage()
                for k, v in m.items():
                    any_value = Any()
                    if isinstance(v, str):
                        any_value.Pack(StringValue(value=v))
                    elif isinstance(v, bool):
                        any_value.Pack(BoolValue(value=v))
                    elif isinstance(v, bytes):
                        any_value.Pack(BytesValue(value=v))
                    elif isinstance(v, int):
                        if v >= 0:
                            bl = v.bit_length()
                            if bl <= 32:
                                any_value.Pack(UInt32Value(value=v))
                            elif bl <= 64:
                                any_value.Pack(UInt64Value(value=v))
                            else:
                                any_value.Pack(StringValue(value=str(v)))
                        else:
                            bl = v.bit_length()
                            if bl <= 32:
                                any_value.Pack(Int32Value(value=v))
                            elif bl <= 64:
                                any_value.Pack(Int64Value(value=v))
                            else:
                                any_value.Pack(StringValue(value=str(v)))
                    else:
                        raise AgentError(f"Unsupported type: {type(v).__name__}")
                    msg.message[k].CopyFrom(any_value)
                path.messages.append(msg)
            paths.paths.append(path)
        data = agent_pb2.ResponseMessage.Data(protocol_paths=paths)

        # pylint: disable=no-member
        return agent_pb2.ResponseMessage(status=agent_pb2.ResponseMessage.Status.OK, data=data)

    def onEpochStart(self, request, context):
        logging.debug('onEpochStart')

        if not request.HasField('ctx'):
            # pylint: disable=no-member
            return agent_pb2.ResponseMessage(
                status=agent_pb2.ResponseMessage.Status.ERROR,
                error="No execution context available")

        try:
            ctx = ExecutionContextSerializer.deserialize(request.ctx)
            self.on_epoch_start(ctx)
        except (AgentError, DeserializationError) as e:
            # pylint: disable=no-member
            return agent_pb2.ResponseMessage(
                status=agent_pb2.ResponseMessage.Status.ERROR,
                error=str(e))

        # pylint: disable=no-member
        return agent_pb2.ResponseMessage(status=agent_pb2.ResponseMessage.Status.OK)

    def onEpochEnd(self, request, context):
        logging.debug('onEpochEnd')

        try:
            self.on_epoch_end()
        except AgentError as e:
            # pylint: disable=no-member
            return agent_pb2.ResponseMessage(
                status=agent_pb2.ResponseMessage.Status.ERROR,
                error=str(e))

        # pylint: disable=no-member
        return agent_pb2.ResponseMessage(status=agent_pb2.ResponseMessage.Status.OK)

    def onTestStart(self, request, context):
        logging.debug('onTestStart')

        if not request.HasField('ctx'):
            # pylint: disable=no-member
            return agent_pb2.ResponseMessage(
                status=agent_pb2.ResponseMessage.Status.ERROR,
                error="No execution context available")

        try:
            ctx = ExecutionContextSerializer.deserialize(request.ctx)
            self.on_test_start(ctx)
        except (AgentError, DeserializationError) as e:
            # pylint: disable=no-member
            return agent_pb2.ResponseMessage(
                status=agent_pb2.ResponseMessage.Status.ERROR,
                error=str(e))

        # pylint: disable=no-member
        return agent_pb2.ResponseMessage(status=agent_pb2.ResponseMessage.Status.OK)

    def onTestEnd(self, request, context):
        logging.debug('onTestEnd')

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
        logging.debug('getData')

        try:
            res = self.get_data()
        except AgentError as e:
            # pylint: disable=no-member
            return agent_pb2.ResponseMessage(
                status=agent_pb2.ResponseMessage.Status.ERROR,
                error=str(e))

        # pylint: disable=no-member
        for r in res:
            record = agent_pb2.ResponseMessage.TestDataRecord(name=r[0], content=r[1])
            data = agent_pb2.ResponseMessage.Data(test_data=record)
            yield agent_pb2.ResponseMessage(status=agent_pb2.ResponseMessage.Status.OK, data=data)

    def skipEpoch(self, request, context):
        logging.debug('skipTest')

        if not request.HasField('ctx'):
            # pylint: disable=no-member
            return agent_pb2.ResponseMessage(
                status=agent_pb2.ResponseMessage.Status.ERROR,
                error="No execution context available")

        try:
            ctx = ExecutionContextSerializer.deserialize(request.ctx)
            res = self.skip_epoch(ctx)
        except (AgentError, DeserializationError) as e:
            # pylint: disable=no-member
            return agent_pb2.ResponseMessage(
                status=agent_pb2.ResponseMessage.Status.ERROR,
                error=str(e))

        # pylint: disable=no-member
        return agent_pb2.ResponseMessage(status=agent_pb2.ResponseMessage.Status.OK, flag=res)

    def redoTest(self, request, context):
        logging.debug('redoTest')

        try:
            res = self.redo_test()
        except AgentError as e:
            # pylint: disable=no-member
            return agent_pb2.ResponseMessage(
                status=agent_pb2.ResponseMessage.Status.ERROR,
                error=str(e))

        # pylint: disable=no-member
        return agent_pb2.ResponseMessage(status=agent_pb2.ResponseMessage.Status.OK, flag=res)

    def onRedo(self, request, context):
        logging.debug('onRedo')

        try:
            self.on_redo()
        except AgentError as e:
            # pylint: disable=no-member
            return agent_pb2.ResponseMessage(
                status=agent_pb2.ResponseMessage.Status.ERROR,
                error=str(e))

        # pylint: disable=no-member
        return agent_pb2.ResponseMessage(status=agent_pb2.ResponseMessage.Status.OK)

    def faultDetected(self, request, context):
        logging.debug('faultDetected')

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
        logging.debug('onFault')

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
        logging.debug('onShutdown')

        try:
            self.on_shutdown()
        except AgentError as e:
            # pylint: disable=no-member
            return agent_pb2.ResponseMessage(
                status=agent_pb2.ResponseMessage.Status.ERROR,
                error=str(e))

        # wait for the completion of this method for maximum 10 seconds
        self.shutdown(10)

        # pylint: disable=no-member
        return agent_pb2.ResponseMessage(status=agent_pb2.ResponseMessage.Status.OK)

    def stopExecution(self, request, context):
        logging.debug('stopExecution')

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

        return response

    ############################################################################################
    ########################               Publisher Methods             #######################
    ############################################################################################

    def startPublisher(self, request, context):
        logging.debug('startPublisher')

        if not request.HasField('publisher_data'):
            # pylint: disable=no-member
            return agent_pb2.ResponseMessage(
                status=agent_pb2.ResponseMessage.Status.ERROR,
                error="No publisher id available")

        try:
            self.start(request.publisher_data.id)
        except AgentError as e:
            # pylint: disable=no-member
            return agent_pb2.ResponseMessage(
                status=agent_pb2.ResponseMessage.Status.ERROR,
                error=str(e))

        # pylint: disable=no-member
        return agent_pb2.ResponseMessage(status=agent_pb2.ResponseMessage.Status.OK)

    def stopPublisher(self, request, context):
        logging.debug('stopPublisher')

        if not request.HasField('publisher_data'):
            # pylint: disable=no-member
            return agent_pb2.ResponseMessage(
                status=agent_pb2.ResponseMessage.Status.ERROR,
                error="No publisher id available")

        try:
            self.stop(request.publisher_data.id)
        except AgentError as e:
            # pylint: disable=no-member
            return agent_pb2.ResponseMessage(
                status=agent_pb2.ResponseMessage.Status.ERROR,
                error=str(e))

        # pylint: disable=no-member
        return agent_pb2.ResponseMessage(status=agent_pb2.ResponseMessage.Status.OK)

    def sendToPublisher(self, request, context):
        logging.debug('sendToPublisher')

        if not request.HasField('publisher_data'):
            # pylint: disable=no-member
            return agent_pb2.ResponseMessage(
                status=agent_pb2.ResponseMessage.Status.ERROR,
                error="No publisher id available")

        data = request.publisher_data.data if request.publisher_data.HasField(
            'data') else b""

        try:
            self.send(request.publisher_data.id, data)
        except AgentError as e:
            # pylint: disable=no-member
            return agent_pb2.ResponseMessage(
                status=agent_pb2.ResponseMessage.Status.ERROR,
                error=str(e))

        # pylint: disable=no-member
        return agent_pb2.ResponseMessage(status=agent_pb2.ResponseMessage.Status.OK)

    def receiveFromPublisher(self, request, context):
        logging.debug('receiveFromPublisher')

        if not request.HasField('publisher_data'):
            # pylint: disable=no-member
            return agent_pb2.ResponseMessage(
                status=agent_pb2.ResponseMessage.Status.ERROR,
                error="No publisher id available")

        try:
            res = self.receive(request.publisher_data.id)
        except AgentError as e:
            # pylint: disable=no-member
            return agent_pb2.ResponseMessage(
                status=agent_pb2.ResponseMessage.Status.ERROR,
                error=str(e))

        # pylint: disable=no-member
        data = agent_pb2.ResponseMessage.Data(raw_data=res)

        # pylint: disable=no-member
        return agent_pb2.ResponseMessage(status=agent_pb2.ResponseMessage.Status.OK, data=data)

    def dataAvailableToPublisher(self, request, context):
        logging.debug('dataAvailableToPublisher')

        if not request.HasField('publisher_data'):
            # pylint: disable=no-member
            return agent_pb2.ResponseMessage(
                status=agent_pb2.ResponseMessage.Status.ERROR,
                error="No publisher id available")

        try:
            res = self.data_available(request.publisher_data.id)
        except AgentError as e:
            # pylint: disable=no-member
            return agent_pb2.ResponseMessage(
                status=agent_pb2.ResponseMessage.Status.ERROR,
                error=str(e))

        # pylint: disable=no-member
        return agent_pb2.ResponseMessage(status=agent_pb2.ResponseMessage.Status.OK, flag=res)
