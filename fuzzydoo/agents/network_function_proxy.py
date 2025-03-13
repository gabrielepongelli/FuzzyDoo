# pylint: disable=too-many-lines

import os
import argparse
import sys
import json
import logging
import threading
import asyncio
import time
import re
import io
from typing import Sequence, override, Any, cast
from collections.abc import Callable
from ipaddress import ip_network
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from dataclasses import dataclass

import requests
import requests.cookies
import iptc
import yaml
import mitmproxy
import mitmproxy.ctx
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.options import Options
from mitmproxy.proxy import commands, context, events, layer, layers, mode_specs
from mitmproxy.certs import Cert
from mitmproxy import http, tls
from openapi_core import OpenAPI
from openapi_core.contrib.requests import RequestsOpenAPIRequest, RequestsOpenAPIResponse
from openapi_core.exceptions import OpenAPIError
from openapi_spec_validator.validation.exceptions import OpenAPIValidationError
from scapy.all import Packet, wrpcap, Ether, IP, TCP  # pylint: disable=no-name-in-module

from ..agent import Agent, ExecutionContext
from ..utils.threads import EventStoppableThread, with_thread_safe_get_set, AsyncioThreadSafeEvent
from ..utils.register import register
from ..utils.network import container_to_addresses
from ..utils.other import first_true, run_as_root
from .grpc_agent import GrpcClientAgent, GrpcServerAgent

from ..utils.errs import *


class MyHttpLayer(layers.HttpLayer):
    """Custom HTTP layer that supports HTTP/2 prior knowledge connections.

    This class extends the mitmproxy HttpLayer to handle HTTP/2 connections that use the prior 
    knowledge mode, where the client immediately starts with the HTTP/2 protocol without first 
    negotiating via HTTP/1.1 or TLS ALPN.

    The class overrides the `_handle_event` method to properly manage HTTP/2 connections when 
    `prior_knowledge` is `True`, allowing for direct HTTP/2 communication without the usual 
    protocol negotiation step.
    """

    prior_knowledge: bool
    """Indicates whether this layer is handling an HTTP/2 prior knowledge connection."""

    def __init__(self, ctx: context.Context, mode: layers.http.HTTPMode, prior_knowledge: bool = False):
        super().__init__(ctx, mode)
        self.prior_knowledge = prior_knowledge

    @override
    def _handle_event(self, event: events.Event):
        if not self.prior_knowledge:
            yield from super()._handle_event(event)
        elif isinstance(event, events.Start):
            # pylint: disable=protected-access
            http_conn = layers.http._http2.Http2Server(self.context.fork())
            self.connections.setdefault(self.context.client, http_conn)
            yield from self.event_to_child(self.connections[self.context.client], event)
            if self.mode is layers.http.HTTPMode.upstream:
                proxy_mode = self.context.client.proxy_mode
                assert isinstance(proxy_mode, mode_specs.UpstreamMode)
                self.context.server.via = (proxy_mode.scheme, proxy_mode.address)
        elif isinstance(event, events.ConnectionEvent):
            # pylint: disable=protected-access
            if (
                event.connection == self.context.server
                and self.context.server not in self.connections
            ):
                # We didn't do anything with this connection yet, now the peer is doing something.
                if isinstance(event, events.ConnectionClosed):
                    # The peer has closed it - let's close it too!
                    yield commands.CloseConnection(event.connection)
                elif isinstance(event, (events.DataReceived, layers.quic._events.QuicStreamEvent)):
                    # The peer has sent data or another connection activity occurred.
                    # This can happen with HTTP/2 servers that already send a settings frame.
                    child_layer = layers.http._http2.Http2Client(self.context.fork())
                    self.connections[self.context.server] = child_layer
                    yield from self.event_to_child(child_layer, events.Start())
                    yield from self.event_to_child(child_layer, event)
                else:
                    raise AssertionError(f"Unexpected event: {event}")
            else:
                handler = self.connections[event.connection]
                yield from self.event_to_child(handler, event)
        else:
            yield from super()._handle_event(event)


@with_thread_safe_get_set
@dataclass
class ContainerInfo:
    """Represents information about a container."""

    name: str
    """The name of the container."""

    aliases: list[str]
    """A list of network aliases for the container."""

    ip: str | None
    """The IP address of the container, if available."""

    mac: str | None
    """The MAC address of the container, if available."""

    cert: Cert | None
    """The TLS certificate associated with the container, if available."""

    specs: list[OpenAPI]
    """A list of OpenAPI specifications associated with the container."""

    def __init__(self, name: str, aliases: list[str] | None = None, ip: str | None = None, mac: str | None = None, cert: Cert | None = None, specs: list[OpenAPI] | None = None):
        self.name = name
        self.aliases = aliases or []
        self.ip = ip
        self.mac = mac
        self.cert = cert
        self.specs = specs or []


class ContainerAddressGetter(EventStoppableThread):
    """A thread that continuously attempts to retrieve the network addresses of a specified container."""

    on_found_cb: Callable[[str, Sequence[str]], None]
    """Callback function to be called when the container's addresses are found. It receives the 
    container name and a sequence of addresses as arguments."""

    container_name: str
    """The name of the container whose addresses are to be retrieved."""

    network_name: str
    """The name of the network on which to look for the container."""

    def __init__(self, container_name: str, network_name: str, on_found_cb: Callable[[str, Sequence[str]], None]) -> None:
        """Initialize a `ContainerAddressGetter` instance.

        Args:
            container_name: The name of the container whose addresses are to be retrieved.
            network_name: The name of the network on which to look for the container.
            on_found_cb: A callback function to be called when the container's addresses are found. 
                It receives the container name and a sequence of addresses as arguments.
        """

        super().__init__()
        self.on_found_cb = on_found_cb
        self.container_name = container_name
        self.network_name = network_name

    @override
    def run(self):
        while not self.stop_event.is_set():
            time.sleep(0.1)
            if addresses := container_to_addresses(self.container_name, self.network_name):
                self.on_found_cb(self.container_name, addresses)
                break


class PriorKnowledgeSupportAddon:
    """Addon for mitmproxy to support HTTP/2 prior knowledge connections.

    This addon modifies the behavior of mitmproxy to handle HTTP/2 connections that use the 
    prior knowledge mode. In this mode, the client starts communication using HTTP/2 directly 
    without the usual HTTP/1.1 or TLS ALPN negotiation.
    """

    def next_layer(self, data: layer.NextLayer):
        if not isinstance(data.layer, layers.HttpLayer):
            return

        preface = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
        data_client = data.data_client()
        if len(data_client) < len(preface):
            return

        if data_client[:len(preface)] == preface:
            data.layer = MyHttpLayer(
                data.context,
                cast(layers.HttpLayer, data.layer).mode,
                prior_knowledge=True
            )


class IgnoreClientConnectionAddon:
    """Addon for mitmproxy to ignore connections from specified client hosts.

    This addon allows mitmproxy to bypass processing for connections originating from certain 
    client hosts. It checks the client's IP address against a list of ignored hosts and, if a 
    match is found, configures the connection to be ignored.

    The addon supports both TCP and UDP transport protocols, and it can be configured to either 
    show or hide ignored hosts based on mitmproxy's options.
    """

    def next_layer(self, data: layer.NextLayer):
        ignored_hosts = mitmproxy.ctx.options.ignore_hosts
        for host in ignored_hosts:
            if host == data.context.client.peername[0]:
                if data.context.client.transport_protocol == "tcp":
                    layer_cls = layers.TCPLayer
                else:
                    layer_cls = layers.UDPLayer

                data.layer = layer_cls(
                    data.context,
                    ignore=not mitmproxy.ctx.options.show_ignored_hosts
                )
                break


class OpenAPICheckerAddon:
    """Addon for mitmproxy to validate HTTP requests and responses against OpenAPI specifications.

    This addon is designed to ensure that HTTP traffic conforms to predefined OpenAPI 
    specifications. It intercepts HTTP requests and responses, validates them against the OpenAPI 
    specs associated with the target container, and logs any discrepancies.
    """

    containers: dict[str, ContainerInfo]
    """A dictionary mapping container names to their respective `ContainerInfo` objects, which include OpenAPI specifications."""

    container_aliases: dict[str, str]
    """A dictionary mapping container aliases to their canonical names."""

    error: Exception | None
    """Stores the last validation error encountered, if any."""

    def __init__(self, containers: dict[str, ContainerInfo], container_aliases: dict[str, str]):
        """Initialize the OpenAPICheckerAddon.

        Args:
            containers: A dictionary mapping container names to their respective `ContainerInfo` 
                objects, which include OpenAPI specifications.
            container_aliases: A dictionary mapping container aliases to their canonical names.
        """

        self.containers = containers
        self.container_aliases = container_aliases
        self.error = None

    def _replace_alias(self, alias: str) -> str:
        """Replace a container alias with its corresponding IP address.

        This function checks if the given alias is present in the container aliases mapping.
        If it is, it retrieves the canonical container name and returns the associated IP address.
        If the alias is not found, it returns the alias unchanged.

        Args:
            alias: The alias of the container to be replaced.

        Returns:
            str: The IP address of the container if the alias is found, otherwise the original alias.
        """

        if alias not in self.container_aliases:
            return alias

        container = self.container_aliases[alias]
        return self.containers[container].ip

    def _patch_ip_addresses(self, data: str) -> str:
        """Replace IP addresses in the given JSON data with their corresponding container aliases

        Args:
            data: The JSON data containing IP addresses.

        Returns:
            str: The modified JSON data with IP addresses replaced by their corresponding container aliases.
        """

        # for "ipv4Address": "any string"
        data = re.sub(
            r'("ipv4Address":\s*")([^"]*)(")',
            lambda m: m.group(1) + self._replace_alias(m.group(2)) + m.group(3),
            data
        )

        def replace_array(_match):
            array_content = _match.group(2)
            updated_array = re.sub(
                r'"([^"]*)"',
                lambda m: f'"{self._replace_alias(m.group(1))}"',
                array_content
            )
            return _match.group(1) + updated_array + _match.group(3)

        # for "ipv4Addresses": ["any string", ...]
        data = re.sub(r'("ipv4Addresses":\s*\[)([^\]]*)(\])', replace_array, data)

        return data

    def _to_request(self, req: http.Request) -> RequestsOpenAPIRequest:
        """Convert a mitmproxy's HTTP Request object to a `RequestsOpenAPIRequest` object.

        It extracts the necessary information from the HTTP request, such as the method, URL, 
        headers, and cookies, and constructs a new RequestsOpenAPIRequest object with this 
        information. If the HTTP request contains a content body, the function attempts to patch 
        any IP addresses in the content body with their corresponding container aliases.

        Args:
            req: The mitmproxy's HTTP Request object to convert.

        Returns:
            RequestsOpenAPIRequest: The converted HTTP Request.
        """

        url = urlparse(req.url, scheme=req.scheme)
        args = {
            "method": req.method,
            "url": f"{url.scheme}://{url.netloc}{url.path}",
            "headers": dict(req.headers),
            "cookies": dict(req.cookies)
        }

        if req.content:
            try:
                args['json'] = json.loads(self._patch_ip_addresses(json.dumps(req.json())))
            except (json.JSONDecodeError, UnicodeDecodeError):
                try:
                    if req.urlencoded_form:
                        args['data'] = req.urlencoded_form
                    else:
                        try:
                            args['data'] = req.text
                        except ValueError:
                            args['data'] = req.content
                except ValueError:
                    args['data'] = req.raw_content

        if url.query:
            args['params'] = parse_qs(url.query)

        return RequestsOpenAPIRequest(requests.Request(**args))

    def _to_response(self, res: http.Response) -> RequestsOpenAPIResponse:
        """Converts a mitmproxy's HTTP Response object to a `RequestsOpenAPIResponse` object.

        It extracts the necessary information from the HTTP response, such as the status code, 
        reason, cookies, and headers, and constructs a new `RequestsOpenAPIResponse` object with 
        this information. If the HTTP response contains a content body, the function attempts to 
        patch any IP addresses in the content body with their corresponding container aliases.

        Args:
            res: The mitmproxy's HTTP Response object to convert.

        Returns:
            RequestsOpenAPIResponse: The converted HTTP Response.
        """

        response = requests.Response()
        response.status_code = res.status_code
        response.reason = res.reason
        response.cookies = requests.cookies.cookiejar_from_dict(res.cookies)
        response.headers = dict(res.headers)

        try:
            try:
                content = self._patch_ip_addresses(res.text).encode()
            except ValueError:
                content = res.content
        except ValueError:
            content = res.raw_content
        response.raw = io.BytesIO(content)

        return RequestsOpenAPIResponse(response)

    def request(self, flow: http.HTTPFlow):
        ip = flow.server_conn.peername[0]
        container = first_true(self.containers.values(), default=None, pred=lambda c: c.ip == ip)
        req = self._to_request(flow.request)

        for spec in container.specs:
            try:
                spec.validate_request(req)
            except OpenAPIError as e:
                msg = f"Invalid OpenAPI request to {container.name}: {e}"
                logging.getLogger().error(msg)
                self.error = Exception(msg)

    def response(self, flow: http.HTTPFlow):
        ip = flow.server_conn.peername[0]
        container = first_true(self.containers.values(), default=None, pred=lambda c: c.ip == ip)
        req = self._to_request(flow.request)
        res = self._to_response(flow.response)

        for spec in container.specs:
            try:
                spec.validate_response(req, res)
            except OpenAPIError as e:
                msg = f"Invalid OpenAPI response from {container.name}: {e}"
                logging.getLogger().error(msg)
                self.error = Exception(msg)

        if not res.response.raw.closed:
            res.response.raw.close()


class TLSCustomCertAddon:
    """Addon for mitmproxy to customize the TLS certificates used by the agent.

    This addon allows the user to specify custom TLS certificates that will be used by the agent
    when establishing secure connections with remote servers. This can be useful in scenarios where
    the default TLS certificates provided by the agent are not trusted by the remote server.
    """

    containers: dict[str, ContainerInfo]
    """A dictionary mapping container names to their respective `ContainerInfo` objects, which include TLS certificates."""

    def __init__(self, containers: dict[str, ContainerInfo]):
        """Initialize a new TLSCustomCertAddon.

        Args:
            containers: A dictionary mapping container names to their respective `ContainerInfo` 
                objects. Each `ContainerInfo` object contains details about the container, 
                including its TLS certificate.
        """
        self.containers = containers

    def tls_start_client(self, data: tls.TlsData) -> None:
        cert = first_true(
            self.containers.values(), default=None,
            pred=lambda c: c.ip == data.context.server.peername[0]
        )
        data.context.client.mitmcert = cert


class PCAPExportAddon:
    """An addon for mitmproxy that captures and exports network traffic in PCAP format.

    This addon intercepts HTTP requests and responses, converts them into network packets,
    and stores them for later export as a PCAP file. It maintains the correct sequence of
    packets and handles both the request and response phases of HTTP communications.
    """

    containers: dict[str, ContainerInfo]
    """A dictionary mapping container names to their respective `ContainerInfo` objects, which include network details."""

    packets: list[Packet]
    """A list to store the captured network packets."""

    def __init__(self, containers: dict[str, ContainerInfo]):
        self.containers = containers
        self.packets = []
        self._sessions: dict[str, dict[str, Any]] = {}

    def _add_packet(self, src: tuple[str, int], dst: tuple[str, int], content: bytes):
        """Add a network packet to the list of captured packets.

        This function constructs a network packet using the provided source and destination
        addresses and content, then appends it to the internal list of packets. It also manages
        the sequence number for the packet to ensure correct ordering.

        Args:
            src: A tuple containing the source IP address and port.
            dst: A tuple containing the destination IP address and port.
            content: The content of the packet to be added.
        """

        src_key = (src[0], src[1], dst[0], dst[1])
        session = self._sessions.get(src_key, None)
        if session is None:
            session = {'seq': 1}
            self._sessions[src_key] = session
        seq = session['seq']

        l2 = Ether()
        l3 = IP(src=src[0], dst=dst[0])
        l4 = TCP(sport=src[1], dport=dst[1], flags=0, seq=seq)
        packet = l2 / l3 / l4 / content
        self.packets.append(packet)
        session['seq'] = seq + len(content)

    def request(self, flow: http.HTTPFlow):
        req = flow.request
        proto = f'{req.method} {req.path} {req.http_version}\r\n'
        payload = bytearray()
        payload.extend(proto.encode('ascii'))
        payload.extend(bytes(req.headers))
        payload.extend(b'\r\n')
        payload.extend(req.raw_content)

        self._add_packet(flow.client_conn.peername, flow.server_conn.peername, bytes(payload))

    def response(self, flow: http.HTTPFlow):
        res = flow.response
        headers = res.headers.copy()
        if res.http_version.startswith('HTTP/2'):
            headers.setdefault('content-length', str(len(res.raw_content)))
            proto = f'{res.http_version} {res.status_code}\r\n'
        else:
            headers.setdefault('Content-Length', str(len(res.raw_content)))
            proto = f'{res.http_version} {res.status_code} {res.reason}\r\n'

        payload = bytearray()
        payload.extend(proto.encode('ascii'))
        payload.extend(bytes(headers))
        payload.extend(b'\r\n')
        payload.extend(res.raw_content)

        self._add_packet(flow.server_conn.peername, flow.client_conn.peername, bytes(payload))

    def export(self) -> bytes:
        """Export captured network packets in PCAP format.

        This function processes the captured network packets, fixes their MAC addresses
        based on the container information, and exports them in PCAP format.

        Returns:
            bytes: The exported PCAP data as a byte string.
        """

        # fix all the MAC addresses of the packets recorded until now
        n = len(self.packets)
        for idx, p in enumerate(self.packets):
            if idx == n:
                break

            src_ip = p[IP].src
            dst_ip = p[IP].dst
            src_cont = first_true(self.containers.values(), default=None, pred=lambda c: c.ip == src_ip)
            dst_cont = first_true(self.containers.values(), default=None, pred=lambda c: c.ip == dst_ip)
            p[Ether].src = src_cont.mac
            p[Ether].dst = dst_cont.mac

        pcap_bytes_io = io.BytesIO()

        # this is needed because wrpcap calls close() at the end
        close_fn = pcap_bytes_io.close
        pcap_bytes_io.close = lambda: None
        wrpcap(pcap_bytes_io, self.packets[:n])

        pcap_bytes_io.close = close_fn
        res = pcap_bytes_io.getvalue()
        pcap_bytes_io.close()

        return res


class ThreadedMitmProxy(threading.Thread):
    """A threaded wrapper for running a mitmproxy instance with custom addons and options.

    This class extends `threading.Thread` to run a mitmproxy instance in a separate thread,
    allowing for asynchronous operation.
    """

    def __init__(self, user_addons: list, **options: Any) -> None:
        """Initialize a new instance of the `ThreadedMitmProxy` class.

        Args:
            user_addons: A list of user-defined addons to be added to the mitmproxy instance.
            **options: Additional options to configure the mitmproxy instance.
        """

        self._loop = asyncio.new_event_loop()

        self._master = DumpMaster(Options(), loop=self._loop)

        self._user_addons = user_addons
        self._master.addons.add(*user_addons)
        self._master.addons.remove(self._master.addons.get('DisableH2C'.lower()))

        # set the options after the addons since some options depend on addons
        self._master.options.update(**options)

        self._ignored: list[str] = options.get('ignore_hosts', [])

        self._update_event: asyncio.Event | None = None
        self._exit_event: asyncio.Event | None = None
        self._options_to_update: dict = {}

        super().__init__()

    async def _async_update_options(self):
        """Asynchronously update options for the mitmproxy instance.

        This method continuously waits for either an update event or an exit event.
        When an update event is triggered, it applies the new options to the mitmproxy instance.
        The method exits when the exit event is set.

        The method uses two asyncio events:
        - `_update_event`: Triggered when new options need to be applied.
        - `_exit_event`: Triggered when the method should terminate.

        It also uses `_options_to_update`, which is expected to be a dictionary containing the new 
        options to be applied to mitmproxy.
        """

        update_task = asyncio.create_task(self._update_event.wait(), name="update")
        exit_task = asyncio.create_task(self._exit_event.wait(), name="exit")
        while True:
            _, _ = await asyncio.wait(
                [update_task, exit_task],
                return_when=asyncio.FIRST_COMPLETED
            )

            if self._update_event.is_set():
                self._master.options.update(**self._options_to_update)
                self._update_event.clear()
                update_task = asyncio.create_task(self._update_event.wait(), name="update")

            if self._exit_event.is_set():
                break

        update_task.cancel()

    async def _async_run(self):
        """Asynchronously run the mitmproxy master and option updater."""

        master_run = asyncio.create_task(self._master.run(), name="mitmproxy proxy")
        option_update = asyncio.create_task(self._async_update_options(), name="mitmproxy updater")
        await master_run
        await option_update

    @override
    def run(self) -> None:
        try:
            asyncio.set_event_loop(self._loop)

            self._update_event = AsyncioThreadSafeEvent()
            self._update_event.clear()

            self._exit_event = AsyncioThreadSafeEvent()
            self._exit_event.clear()

            self._loop.run_until_complete(self._async_run())
        except KeyboardInterrupt:
            pass
        finally:
            self._loop.run_until_complete(self._loop.shutdown_asyncgens())
            self._loop.close()

    @override
    def join(self, timeout=None):
        self._master.shutdown()
        self._exit_event.set()
        return super().join(timeout)

    def ignore(self, ip: str):
        """Ignore a specific IP address in the proxy.

        This method adds the given IP address to the list of ignored hosts and updates the proxy 
        options accordingly.

        Args:
            ip: The IP address to be ignored by the proxy.
        """

        self._ignored.append(ip)
        self.update_options(ignore_hosts=list(self._ignored))
        logging.getLogger().warning('Host %s ignored', ip)

    def add_addons(self, *addons):
        """Add new addons to the mitmproxy instance.

        This method extends the list of user-defined addons and adds them to the mitmproxy master.

        Args:
            *addons: Variable length argument list of addon objects to be added.
        """

        self._user_addons.extend(addons)
        self._master.addons.add(*addons)

    def update_options(self, **options):
        """Update the options for the mitmproxy instance.

        This method sets new options for the mitmproxy instance and triggers an update event
        to apply these options asynchronously.

        Args:
            **options: Arbitrary keyword arguments representing the new options to be applied.
        """

        self._options_to_update = options
        self._update_event.set()

    def reset(self):
        """Reset the proxy settings and clear user-defined addons.

        This method clears the list of ignored hosts and resets the proxy options. It also removes 
        all user-defined addons from the mitmproxy instance.
        """

        self._ignored = []
        self.update_options(ignore_hosts=list(self._ignored), mode=[])
        for addon in self._user_addons:
            self._master.addons.remove(self._master.addons.get(addon.__class__.__name__.lower()))
        self._user_addons = []


@register(Agent)
class NetworkFunctionProxyAgent(GrpcClientAgent):
    """Agent that controls a network proxy specifically crafted for network functions."""

    # pylint: disable=useless-parent-delegation
    @override
    def set_options(self, **kwargs):
        """Set options for the agent.

        This method should be called before passing the agent to the engine.

        Args:
            kwargs: Additional keyword arguments. It must contain the following keys:
                - `'compose_yaml_path'`: The path to the `docker-compose.yaml` file.
                - `'network_name'`: The name of the network inside the docker compose file that 
                        will be monitored.
                - `'certs_path'`: The path of a directory containing all the TLS certificates that 
                        will be used. Each certificate must be in pem format, and its name must be 
                        the name of the network function whose certificate belongs to.
                - `'exclude'` (optional): A list of strings representing the names of the 
                        containers that will be excluded from the monitoring process.
                - `'proxy_port'` (optional): An integer representing the TCP port on which the 
                        monitor will work. Defaults to `8080`.
                - `'openapi_path'` (optional): The path of a directory containing all the OpenAPI 
                        specification files on which NFs' requests and responses will be checked. 
                        If not provided, the adherence to the OpenAPI specification will be 
                        skipped. No value is provided as default.

        Raises:
            AgentError: If some error occurred at the agent side. In this case the method 
                `stop_execution` is called.
        """
        super().set_options(**kwargs)

    @override
    def skip_epoch(self, ctx: ExecutionContext) -> bool:
        return False

    @override
    def redo_test(self) -> bool:
        return False

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


class TlsCertLoader(EventStoppableThread):
    """A thread class for loading TLS certificates from a specified directory.

    The `TlsCertLoader` class provide functionality for loading TLS certificates from a given 
    directory path. It continuously monitors the specified directory for PEM files, reads their 
    content, and loads them as `Cert` objects into a dictionary.
    """

    path: Path
    """The directory path where the TLS certificate files are located."""

    certs: dict[str, Cert]
    """A dictionary mapping certificate filenames to their respective `Cert` objects."""

    def __init__(self, path: Path):
        super().__init__()
        self.path = path
        self.certs = {}

    def run(self):
        for p in self.path.iterdir():
            if self.stop_event.is_set():
                break

            if p.is_file() and p.name.endswith('.pem'):
                with open(p, 'rb') as f:
                    pem_cert = f.read()

                if pem_cert.startswith(b'-----BEGIN CERTIFICATE-----') \
                        and pem_cert.endswith(b'-----END CERTIFICATE-----\n'):
                    c = Cert.from_pem(pem_cert)
                    self.certs[p.name] = c
                    logging.getLogger().warning('Loaded certificate at %s', p)
                else:
                    logging.getLogger().warning('Invalid certificate at %s', p)


class OpenAPISpecsLoader(EventStoppableThread):
    """A thread class for loading OpenAPI specifications from a specified directory.

    The `OpenAPISpecsLoader` class provide functionality for loading OpenAPI specifications from a 
    given directory path. It continuously monitors the specified directory for OpenAPI files, reads 
    their content, and loads them as `OpenAPI` objects into a dictionary.
    """

    path: Path
    """The directory path where the OpenAPI specification files are located."""

    specs: dict[str, OpenAPI]
    """A dictionary mapping specification filenames to their respective `OpenAPI` objects."""

    def __init__(self, path: Path):
        super().__init__()
        self.path = path
        self.specs = {}

    def run(self):
        for p in self.path.iterdir():
            if self.stop_event.is_set():
                break

            if p.is_file() and p.name.endswith('.yaml'):
                try:
                    with open(p, 'r', encoding='utf8') as f:
                        openapi = OpenAPI.from_file(f, base_uri=p.absolute().as_uri())
                except OpenAPIValidationError:
                    continue

                self.specs[p.name] = openapi
                logging.getLogger().warning('Loaded OpenAPI specification at %s', p)


class NetworkFunctionProxyServerAgent(GrpcServerAgent):
    """Server agent that controls a network proxy specifically crafted for network functions.

    Note: This agent needs root privileges in order to work properly.
    """

    DEFAULT_OPTIONS: dict[str, str | Path | list[str] | int | None] = {
        'compose_yaml_path': None,
        'network_name': None,
        'certs_path': None,
        'exclude': [],
        'proxy_port': 8080
    }

    options: dict[str, str | Path | list[str] | int | None]
    """Options currently set on the agent."""

    def __init__(self, **kwargs):
        super().__init__(None, **kwargs)

        self.options = dict(self.DEFAULT_OPTIONS)
        self.set_options(**kwargs)

        self._proxy: ThreadedMitmProxy | None = None
        self._network_ip: str = ''
        self._iface_name: str = ''
        self._network_name: str = ''
        self._address_getters: list[ContainerAddressGetter] = []
        self._tls_cert_loader: TlsCertLoader | None = None
        self._openapi_specs_loader: OpenAPISpecsLoader | None = None
        self._pcap_exporter: PCAPExportAddon | None = None
        self._openapi_checker: OpenAPICheckerAddon | None = None

    @override
    def set_options(self, **kwargs):
        if 'compose_yaml_path' in kwargs:
            self.options['compose_yaml_path'] = Path(kwargs['compose_yaml_path'])
            logging.getLogger().warning('Set %s = %s', 'compose_yaml_path', self.options['compose_yaml_path'])

        if 'network_name' in kwargs:
            self.options['network_name'] = kwargs['network_name']
            logging.getLogger().warning('Set %s = %s', 'network_name', self.options['network_name'])

        if 'certs_path' in kwargs:
            self.options['certs_path'] = Path(kwargs['certs_path'])
            logging.getLogger().warning('Set %s = %s', 'certs_path', self.options['certs_path'])
            if self._tls_cert_loader is not None:
                self._tls_cert_loader.join()
            self._tls_cert_loader = TlsCertLoader(self.options['certs_path'])
            self._tls_cert_loader.start()

        if 'exclude' in kwargs:
            self.options['exclude'] = kwargs['exclude']
            logging.getLogger().warning('Set %s = %s', 'exclude', self.options['exclude'])

        if 'proxy_port' in kwargs:
            self.options['proxy_port'] = kwargs['proxy_port']
            logging.getLogger().warning('Set %s = %s', 'proxy_port', self.options['proxy_port'])

        if 'openapi_path' in kwargs:
            self.options['openapi_path'] = Path(kwargs['openapi_path'])
            logging.getLogger().warning('Set %s = %s', 'openapi_path', self.options['openapi_path'])
            if self._openapi_specs_loader is not None:
                self._openapi_specs_loader.join()
            self._openapi_specs_loader = OpenAPISpecsLoader(self.options['openapi_path'])
            self._openapi_specs_loader.start()

    @override
    def reset(self):
        self.options = dict(self.DEFAULT_OPTIONS)
        self._pause_mitmproxy()
        self._network_ip = ''
        self._iface_name = ''
        self._network_name = ''
        self._address_getters = []
        self._tls_cert_loader = None
        self._openapi_specs_loader = None
        self._pcap_exporter = None
        self._openapi_checker = None

    def _add_iptable_rule(self, target_iface: str, target_net: str, redirect_port: int):
        """Add a redirection rule to the iptable rules.

        The following rule will be added:
        `iptables -t nat -A PREROUTING -i <target_iface> -s <target_net> -p tcp -j REDIRECT --to-port <redirect_port>`

        Args:
            target_iface: The name of the interface whose traffic will be redirected.
            target_net: The IP range that will be affected by the redirection.
            redirect_port: The port number where the traffic will be redirected to.

        Raises:
            AgentError: If an error occurs while applying the rule.
        """

        try:
            # access the nat table and PREROUTING chain
            table = iptc.Table(iptc.Table.NAT)
            chain = iptc.Chain(table, "PREROUTING")

            # create a new rule
            rule = iptc.Rule()
            rule.protocol = "tcp"

            # add a match for the source network
            rule.create_match("tcp")
            rule.src = target_net

            # specify the incoming interface
            rule.in_interface = target_iface

            # add the REDIRECT target
            target = rule.create_target("REDIRECT")
            target.to_ports = str(redirect_port)

            chain.append_rule(rule)
        except iptc.IPTCError as e:
            msg = f"Error while modifying iptables: {e}"
            logging.getLogger().error(msg)
            raise AgentError(msg) from e
        except ValueError as e:
            msg = str(e)
            logging.getLogger().error(msg)
            raise AgentError(msg) from e

    def _remove_iptable_rule(self, target_iface: str, target_net: str, redirect_port: int):
        """Remove the redirection rule to the iptable rules (see `_add_iptable_rule`).

        The following rule will be added:
        `iptables -t nat -D PREROUTING -i <target_iface> -s <target_net> -p tcp -j REDIRECT --to-port <redirect_port>`

        Args:
            target_iface: The name of the interface whose traffic is redirected.
            target_net: The IP range that is affected by the redirection.
            redirect_port: The port number where the traffic is redirected to.

        Raises:
            AgentError: If an error occurs while removing the rule.
        """

        try:
            # access the nat table and PREROUTING chain
            table = iptc.Table(iptc.Table.NAT)
            chain = iptc.Chain(table, "PREROUTING")
            for rule in chain.rules:
                if rule.protocol == "tcp" and ip_network(rule.src) == ip_network(target_net) \
                        and rule.in_interface == target_iface and rule.target.name == "REDIRECT" \
                        and rule.target.to_ports == str(redirect_port):
                    chain.delete_rule(rule)
                    return
        except iptc.IPTCError as e:
            msg = f"Error while modifying iptables: {e}"
            logging.getLogger().error(msg)
            raise AgentError(msg) from e
        except ValueError as e:
            msg = str(e)
            logging.getLogger().error(msg)
            raise AgentError(msg) from e

    def _get_container_aliases(self, configs: dict) -> dict[str, str]:
        """Get container aliases from the compose configuration.

        Args:
            configs: The compose configuration.

        Returns:
            dict[str, str]: A dictionary where the keys are container names and the values are their aliases.
        """

        aliases = {}
        for container_config in configs['services'].values():
            container_name = container_config['container_name']
            if container_name in self.options['exclude']:
                continue

            if 'networks' in container_config:
                for network_name, network_config in container_config['networks'].items():
                    if network_name == self.options['network_name']:
                        for alias in network_config.get('aliases', []):
                            aliases[alias] = container_name
                        break
        return aliases

    def _get_network_data_from_configs(self, configs: dict) -> tuple[str, str, str]:
        """Extract network-related data from the provided configuration dictionary.

        This function retrieves the network IP, interface name, and network name from the given 
        configuration dictionary. It uses the network name specified in the agent's options to 
        locate the correct network configuration.

        Args:
            configs: A dictionary containing the parsed configuration data, typically from a 
                docker-compose.yaml file.

        Returns:
            tuple[str, str, str]: A tuple containing three strings:
                1. The subnet IP address of the network.
                2. The name of the network interface.
                3. The name of the network.

        Raises:
            AgentError: If the specified network is not found in the configuration, if no IP 
                address is found for the network, or if no interface name is found for the network.
        """

        try:
            network = configs['networks'][self.options['network_name']]
        except KeyError as e:
            msg = f"No network named '{self.options['network_name']}' found in {self.options['compose_yaml_path']}"
            logging.getLogger().error(msg)
            raise AgentError(msg) from e

        try:
            for c in network['ipam']['config']:
                if 'subnet' in c:
                    network_ip = c['subnet']
                    break
            else:
                raise KeyError()
        except KeyError as e:
            msg = "No IP address found for network named " \
                + f"'{self.options['network_name']}' in {self.options['compose_yaml_path']}"
            logging.getLogger().error(msg)
            raise AgentError(msg) from e

        try:
            iface_name = network['driver_opts']['com.docker.network.bridge.name']
        except KeyError as e:
            msg = "No interface name found for network named " \
                + f"'{self.options['network_name']}' in {self.options['compose_yaml_path']}"
            logging.getLogger().error(msg)
            raise AgentError(msg) from e

        if 'name' in network:
            network_name = network['name']
        else:
            network_name = self.options['compose_yaml_path'].absolute().parent.name + '_' + \
                self.options['network_name']

        return network_ip, iface_name, network_name

    def _start_mitmproxy(self, containers: dict[str, ContainerInfo], aliases: dict[str, str]):
        """Start the mitmproxy instance with configured addons and settings.

        This method initializes and starts a `ThreadedMitmProxy` instance with various addons for 
        traffic interception, TLS handling, and OpenAPI checking. It sets up the proxy in 
        transparent mode and configures it based on the agent's options.

        Args:
            containers: A dictionary mapping container names to their respective `ContainerInfo` 
                objects, containing details about each container.
            aliases: A dictionary mapping container aliases to their actual names.
        """

        self._pcap_exporter = PCAPExportAddon(containers)
        addons = [
            IgnoreClientConnectionAddon(),
            PriorKnowledgeSupportAddon(),
            TLSCustomCertAddon(containers),
            self._pcap_exporter
        ]

        if 'openapi_path' in self.options:
            self._openapi_checker = OpenAPICheckerAddon(containers, aliases)
            addons.append(self._openapi_checker)

        self._proxy = ThreadedMitmProxy(
            addons,
            mode=['transparent'],
            listen_port=self.options['proxy_port'],
            ignore_hosts=[],
            show_ignored_hosts=False,
            ssl_insecure=True
        )

        self._proxy.start()

    def _pause_mitmproxy(self):
        """Pause the mitmproxy instance and reset associated components.

        This method resets the mitmproxy instance if it exists and clears the PCAP exporter and 
        OpenAPI checker.
        """

        if self._proxy is not None:
            self._proxy.reset()
            self._pcap_exporter = None
            self._openapi_checker = None

    def _restart_mitmproxy(self, containers: dict[str, ContainerInfo], aliases: dict[str, str]):
        """Restart the mitmproxy instance with updated configurations and addons.

        This method reinitializes the mitmproxy with new addons and settings based on the current 
        container configurations and aliases. It sets up various addons including PCAP export, TLS 
        handling, and OpenAPI checking (if enabled).

        Args:
            containers: A dictionary mapping container names to their respective `ContainerInfo` 
                objects, containing details about each container.
            aliases: A dictionary mapping container aliases to their actual names.
        """

        self._pcap_exporter = PCAPExportAddon(containers)
        addons = [
            IgnoreClientConnectionAddon(),
            PriorKnowledgeSupportAddon(),
            TLSCustomCertAddon(containers),
            self._pcap_exporter
        ]

        if 'openapi_path' in self.options:
            self._openapi_checker = OpenAPICheckerAddon(containers, aliases)
            addons.append(self._openapi_checker)

        self._proxy.add_addons(*addons)
        self._proxy.update_options(
            mode=['transparent'], listen_port=self.options['proxy_port'],
            ignore_hosts=[], show_ignored_hosts=False,
            ssl_insecure=True
        )

    def _stop_mitmproxy(self):
        """Stop the mitmproxy instance and reset associated components.

        This method stops the mitmproxy instance if it is running and clears the PCAP exporter and 
        OpenAPI checker.
        """

        if self._proxy is not None:
            self._proxy.join()
            self._pcap_exporter = None
            self._openapi_checker = None

    @override
    def on_test_start(self, ctx: ExecutionContext):
        if self.options['compose_yaml_path'] is None:
            msg = "No docker-compose.yaml path specified"
            logging.getLogger().error(msg)
            raise AgentError(msg)

        if self.options['network_name'] is None:
            msg = "No network name specified"
            logging.getLogger().error(msg)
            raise AgentError(msg)

        if self.options['certs_path'] is None:
            msg = "No certs path specified"
            logging.error(msg)
            raise AgentError(msg)

        try:
            with open(self.options['compose_yaml_path'], 'r', encoding='utf8') as f:
                compose_configs = yaml.safe_load(f)
        except yaml.YAMLError as e:
            msg = f"Error loading {self.options['compose_yaml_path']}: {e}"
            logging.getLogger().error(msg)
            raise AgentError(msg) from e

        self._network_ip, self._iface_name, self._network_name = self._get_network_data_from_configs(compose_configs)
        aliases = self._get_container_aliases(compose_configs)

        containers: dict[str, ContainerInfo] = {}
        for container_config in compose_configs['services'].values():
            container_name = container_config['container_name']

            while self._tls_cert_loader.is_alive() \
                    or (self._openapi_specs_loader and self._openapi_specs_loader.is_alive()):
                time.sleep(0.5)

            c = None
            for c in self._tls_cert_loader.certs:
                if container_name in c:
                    break

            specs = []
            if 'openapi_path' in self.options:
                for name, s in self._openapi_specs_loader.specs.items():
                    if name.split('_')[1][1:] == container_name:
                        specs.append(s)

            info = ContainerInfo(container_name, cert=self._tls_cert_loader.certs[c], specs=specs)
            containers[container_name] = info

            def update_addresses(container: str, addresses: tuple[str, str]):
                containers[container].ip = addresses[0]
                containers[container].mac = addresses[1]

            getter = ContainerAddressGetter(container_name, self._network_name, update_addresses)
            self._address_getters.append(getter)

        if self._proxy is None:
            self._start_mitmproxy(containers, aliases)
        else:
            self._restart_mitmproxy(containers, aliases)
        self._add_iptable_rule(self._iface_name, self._network_ip, self.options['proxy_port'])

        for cont in self.options['exclude']:
            getter = ContainerAddressGetter(
                cont, self._network_name, lambda _, addresses: self._proxy.ignore(addresses[0]))
            self._address_getters.append(getter)

        for getter in self._address_getters:
            getter.start()

    @override
    def on_test_end(self):
        self._remove_iptable_rule(self._iface_name, self._network_ip, self.options['proxy_port'])
        self._pause_mitmproxy()

        for getter in self._address_getters:
            getter.join()

        self._address_getters = []

    @override
    def on_shutdown(self):
        self._stop_mitmproxy()

    @override
    def fault_detected(self) -> bool:
        if self._openapi_checker is None:
            return False

        return self._openapi_checker.error is not None

    @override
    def get_data(self) -> list[tuple[str, bytes]]:
        if self._pcap_exporter is None:
            return []

        return [('dump.pcap', self._pcap_exporter.export())]


__all__ = ['NetworkFunctionProxyAgent']


def main():
    parser = argparse.ArgumentParser(
        description='Agent that controls the UERANSIM tools.')
    parser.add_argument('--ip', type=str, help='IP address to listen on')
    parser.add_argument('--port', type=int, help='Port to listen on')

    args = parser.parse_args()

    if os.geteuid() != 0:
        run_as_root()

    if not args.ip or not args.port:
        sys.stderr.write("Error: No IP address and port specified\n")
        sys.exit(1)

    logging.getLogger().setLevel(level=logging.WARNING)

    agent = NetworkFunctionProxyServerAgent(address=args.ip, port=args.port)

    agent.serve()
