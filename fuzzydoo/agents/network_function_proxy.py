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
from typing import Sequence, override, Any
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
from mitmproxy.proxy import layer, layers
from mitmproxy.certs import Cert
from mitmproxy import http, tls, tcp
from mitmproxy.http import status_codes
from mitmproxy.addons.dumper import Dumper
from openapi_core import OpenAPI
from openapi_core.contrib.requests import RequestsOpenAPIRequest, RequestsOpenAPIResponse
from openapi_core.exceptions import OpenAPIError
from scapy.all import Packet, wrpcap, Ether, IP, TCP  # pylint: disable=no-name-in-module
from scapy.contrib import http2
from dotenv import dotenv_values
from more_itertools import first_true

from ..agent import Agent, ExecutionContext
from ..utils.threads import EventStoppableThread, with_thread_safe_get_set, AsyncioThreadSafeEvent
from ..utils.register import register
from ..utils.network import container_to_addresses
from ..utils.other import run_as_root
from .grpc_agent import GrpcClientAgent, GrpcServerAgent

from ..utils.errs import *


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


class Http2OverlayAddon:
    """An addon for mitmproxy that provides enhanced HTTP/2 support and processing capabilities.

    This addon intercepts and processes HTTP/2 traffic, allowing for detailed inspection and 
    analysis of HTTP/2 streams. It maintains session information for each connection and handles 
    various HTTP/2 frame types, including SETTINGS, HEADERS, DATA, and PUSH_PROMISE frames.

    If other custom addons need to place hooks for HTTP/2 requests and responses, they must be 
    added to the addon list of this addon instead of adding them directly to the mitmproxy master.

    Note:
        This addon is designed to work on top of mitmproxy's TCP layer, replacing the default HTTP 
        layer provided by mitmproxy.

    Example:
        Here's how to use the `Http2OverlayAddon` with mitmproxy:

        ```python
        from mitmproxy.tools.dump import DumpMaster
        from mitmproxy.options import Options
        from fuzzydoo.agents.network_function_proxy import Http2OverlayAddon

        class OtherAddon:
            def request(self, flow: http.HttpFlow):
                # ....

            def response(self, flow: http.HttpFlow):
                # ....

        opts = Options(
            listen_host='0.0.0.0',
            listen_port=8080,
            tcp_hosts=[".*"] # to make sure that every flow is processed as a TCP flow
        )
        m = DumpMaster(opts)

        http2_addon = Http2OverlayAddon(
            addons=[OtherAddon()]  # add your custom addons here
        )

        m.addons.add(http2_addon)

        try:
            m.run()
        except KeyboardInterrupt:
            m.shutdown()
        ```

        This example sets up mitmproxy with the Http2OverlayAddon, allowing it to intercept and 
        process HTTP/2 traffic on port 8080.
    """

    addons: list[object]
    """A list of additional addons to be applied to the HTTP/2 layer."""

    dumper: Dumper | None
    """A dumper object for logging purposes."""

    def __init__(self, addons: list[object] | None = None, dumper: Dumper | None = None):
        """Initialize the Http2OverlayAddon.

        Args:
            addons (optional): A list of additional addon objects to be used with this 
                Http2OverlayAddon. Defaults to `[]`.
            dumper (optional): A Dumper object for logging purposes. Defaults to `None`.
        """

        self.addons = addons or []
        self.dumper = dumper

        self._sessions: dict[Any, dict[str, Any]] = {}

    def _get_sessions_key(self, client: tuple[str, int], server: tuple[str, int]) -> Any:
        """Get a session key to use for the client-server pair specified.

        Args:
            client: A tuple containing the client IP address and port.
            server: A tuple containing the server IP address and port.

        Returns:
            Any: The session key.
        """

        return (client[0], client[1], server[0], server[1])

    def tcp_start(self, flow: tcp.TCPFlow):
        skey = self._get_sessions_key(flow.client_conn.peername, flow.server_conn.peername)
        self._sessions[skey] = {
            'server': {
                'ip': flow.server_conn.peername[0],
                'port': flow.server_conn.peername[1],
                'max_header_table_size': 4096,
                'header_table_size': 4096,
                'header_table': None
            },
            'client': {
                'ip': flow.client_conn.peername[0],
                'port': flow.client_conn.peername[1],
                'max_header_table_size': 4096,
                'header_table_size': 4096,
                'header_table': None
            },
            'http2': None,
            'streams': {},
        }

    def _create_stream(self, session: dict[str, Any], stream_id: int, request_ref: int | None = None) -> dict[str, Any]:
        """Create a new stream entry in the session's streams dictionary.

        This function initializes a new stream with the given stream ID in the provided session. If 
        a request reference is provided, it increments the reference count for the existing 
        request. Otherwise, it initializes a new request structure.

        Args:
            session: The session dictionary where the stream will be added.
            stream_id: The unique identifier for the stream to be created.
            request_ref (optional): An optional reference to an existing request. If provided, the 
                reference count for the request is incremented. Defaults to `None`.

        Returns:
            dict[str, Any]: The newly created stream dictionary containing request and response
                structures, along with metadata such as the number of ends, reference count, and
                cancellation status.
        """

        if request_ref is not None:
            request = request_ref
        else:
            request = {
                'method': '',
                'path': '',
                'authority': '',
                'scheme': '',
                'headers': {},
                'data': b""
            }

        stream = {
            'n_ends': 0,
            'cancelled': False,
            'request': request,
            'response': {
                'status': '',
                'headers': {},
                'data': b""
            },
            'mitmproxy_flow': None
        }

        session['streams'][stream_id] = stream
        return stream

    def _handle_settings_frame(self, frame: http2.H2Frame, session: dict[str, Any], src_name: str):
        """Handle an HTTP/2 SETTINGS frame and update the session's settings accordingly.

        This function processes the SETTINGS frame received from a source (client or server) and
        updates the session's settings based on the settings specified in the frame.

        Args:
            frame: The HTTP/2 frame containing the SETTINGS payload to be processed.
            session: The session dictionary that holds the current state and settings for the 
                HTTP/2 connection.
            src_name: The name of the source (either `'client'` or `'server'`) from which the
                SETTINGS frame was received.
        """

        src: dict[str, Any] = session[src_name]

        for setting in frame.payload.settings:
            if setting.id == http2.H2Setting.SETTINGS_HEADER_TABLE_SIZE:
                src['max_header_table_size'] = setting.value
                src['header_table_size'] = setting.value
                src['header_table'] = None

    def _handle_headers_frame(self, frame: http2.H2Frame, session: dict[str, Any], src_name: str, stream_id: int | None = None):
        """Handle an HTTP/2 HEADERS frame and update the session's stream with the parsed headers.

        This function processes the HEADERS frame received from a source (client or server) and
        updates the corresponding stream in the session with the parsed headers.

        Args:
            frame: The HTTP/2 frame containing the HEADERS payload to be processed.
            session: The session dictionary that holds the current state and streams for the HTTP/2 
                connection.
            src_name: The name of the source (either `'client'` or `'server'`) from which the
                HEADERS frame was received.
            stream_id (optional): An optional stream ID to be used for the headers instead of the 
                one contained in the frame. If not provided, the frame's stream ID is used. 
                Defaults to `None`.
        """

        src: dict[str, Any] = session[src_name]

        try:
            src['header_table_size'] = frame.payload.hdrs.getfieldval('max_size')
        except AttributeError:
            pass

        hdr_table: http2.HPackHdrTable | None = src['header_table']
        if hdr_table is None:
            hdr_table = http2.HPackHdrTable(
                dynamic_table_max_size=src['header_table_size'],
                dynamic_table_cap_size=src['max_header_table_size']
            )
            src['header_table'] = hdr_table

        stream_id = frame.stream_id if stream_id is None else stream_id
        stream: dict[str, Any] = session['streams'][stream_id]
        msg: dict[str, Any] = stream['request'] if src_name == 'client' else stream['response']
        text = hdr_table.gen_txt_repr(frame)
        for line in text.splitlines():
            if line[0] == ':':
                k, *val = line.split(' ')
                msg[k[1:]] = " ".join(val)
            else:
                h, *val = line.split(': ')
                msg['headers'][h] = ": ".join(val)

    def _handle_data_frame(self, frame: http2.H2Frame, session: dict[str, Any], src_name: str):
        """Handle an HTTP/2 DATA frame and update the session's stream with the received data.

        This function processes the DATA frame received from a source (client or server) and 
        appends the frame's payload data to the corresponding message (request or response) in the 
        session's stream.

        Args:
            frame: The HTTP/2 frame containing the DATA payload to be processed.
            session: The session dictionary that holds the current state and streams for the HTTP/2 
                connection.
            src_name: The name of the source (either `'client'` or `'server'`) from which the DATA 
                frame was received.
        """

        stream: dict[str, Any] = session['streams'][frame.stream_id]
        msg: dict[str, Any] = stream['request'] if src_name == 'client' else stream['response']
        try:
            msg['data'] += frame.payload.data
        except AttributeError:
            pass

    def _handle_push_promise_frame(self, frame: http2.H2Frame, session: dict[str, Any], src_name: str):
        """Handle an HTTP/2 PUSH_PROMISE frame and create a new stream for the promised request.

        This function processes a PUSH_PROMISE frame, creates a new stream for the promised request,
        and handles the headers contained within the frame.

        Args:
            frame: The HTTP/2 frame containing the PUSH_PROMISE payload to be processed.
            session: The session dictionary that holds the current state and streams for the HTTP/2 
                connection.
            src_name: The name of the source (either `'client'` or `'server'`) from which the
                PUSH_PROMISE frame was received.
        """

        self._create_stream(session, frame.payload.stream_id, request_ref=frame.stream_id)
        self._handle_headers_frame(frame, session, src_name, stream_id=frame.payload.stream_id)

    def _create_mitmproxy_flow(self, tcp_flow: tcp.TCPFlow, session: dict[str, Any], stream_id: int) -> http.HTTPFlow:
        """Create a mitmproxy HTTP flow from a TCP flow and session information.

        Args:
            tcp_flow: The TCP flow containing connection information.
            session: A dictionary containing session information, including streams and requests.
            stream_id: The ID of the stream for which to create the HTTP flow.

        Returns:
            http.HTTPFlow: A newly created HTTP flow object.
        """

        stream: dict[str, Any] = session['streams'][stream_id]

        req: dict[str, Any] = stream['request']
        if isinstance(req, int):
            req = session['streams'][req]

        method: str = req['method']
        scheme: str = req['scheme']
        authority: str = req['authority']
        path: str = req['path']

        headers = http.Headers(
            (
                k.encode("utf-8", "surrogateescape"),
                v.encode("utf-8", "surrogateescape")
            )
            for k, v in req['headers'].items()
        )

        http_flow = http.HTTPFlow(tcp_flow.client_conn, tcp_flow.server_conn)
        http_flow.request = http.Request(
            tcp_flow.server_conn.peername[0],
            tcp_flow.server_conn.peername[1],
            method.encode("utf-8", "surrogateescape"),
            scheme.encode("utf-8", "surrogateescape"),
            authority.encode("utf-8", "surrogateescape"),
            path.encode("utf-8", "surrogateescape"),
            b"HTTP/2.0",
            headers,
            req['data'],
            None,
            time.time(),
            time.time()
        )
        stream['mitmproxy_flow'] = http_flow

        return http_flow

    def _add_mitmproxy_response(self, session: dict[str, Any], stream_id: int):
        """Add a mitmproxy response to the specified HTTP/2 stream in the session.

        This method creates and adds a mitmproxy HTTP response object to the existing HTTP flow for the given stream. It uses the response data stored in the session to construct the 
        mitmproxy response.

        Args:
            session: A dictionary containing the session information, including streams and their 
                associated data.
            stream_id: The ID of the stream for which to add the response.
        """

        stream: dict[str, Any] = session['streams'][stream_id]

        status_code = int(stream['response']['status'])

        headers = http.Headers(
            (
                k.encode("utf-8", "surrogateescape"),
                v.encode("utf-8", "surrogateescape")
            )
            for k, v in stream['response']['headers'].items()
        )

        http_flow: http.HTTPFlow = stream['mitmproxy_flow']
        http_flow.response = http.Response(
            b"HTTP/2.0",
            status_code,
            status_codes.RESPONSES.get(status_code, "").encode(),
            headers,
            stream['response']['data'],
            None,
            time.time(),
            time.time()
        )

    def tcp_message(self, flow: tcp.TCPFlow):
        skey = self._get_sessions_key(flow.client_conn.peername, flow.server_conn.peername)
        session = self._sessions[skey]
        msg = flow.messages[-1]
        src_name = 'client' if msg.from_client else 'server'

        msg_content: bytes = msg.content
        if session['http2'] is None:
            if flow.client_conn.alpn is not None:
                session['http2'] = flow.client_conn.alpn == 'h2'
            elif msg.from_client:
                session['http2'] = msg_content.startswith(http2.H2_CLIENT_CONNECTION_PREFACE)
                if session['http2']:
                    msg_content = msg_content[len(http2.H2_CLIENT_CONNECTION_PREFACE):]
                    if len(msg_content) == 0:
                        return

        if session['http2'] is not None and not session['http2']:
            # ignore non-http2 connections
            return

        frame_seq = http2.H2Seq(msg_content)
        if not isinstance(frame_seq.frames[0], http2.H2Frame):
            session['http2'] = False
            return

        frame: http2.H2Frame
        for frame in frame_seq.frames:
            if 'A' in frame.flags:
                # is an ACK frame so we can ignore it
                continue

            if frame.stream_id not in session['streams']:
                self._create_stream(session, frame.stream_id)
            stream: dict[str, Any] = session['streams'][frame.stream_id]

            if frame.type == http2.H2SettingsFrame.type_id:
                self._handle_settings_frame(frame, session, src_name)
            elif frame.type in {http2.H2HeadersFrame.type_id, http2.H2ContinuationFrame.type_id}:
                self._handle_headers_frame(frame, session, src_name)
            elif frame.type == http2.H2DataFrame.type_id:
                self._handle_data_frame(frame, session, src_name)
            elif frame.type == http2.H2PushPromiseFrame.type_id:
                self._handle_push_promise_frame(frame, session, src_name)
            elif frame.type == http2.H2ResetFrame.type_id:
                stream['cancelled'] = True

            if 'ES' in frame.flags:
                # the stream is ended by this peer
                stream['n_ends'] += 1

            if stream['n_ends'] == 1 \
                    and not isinstance(stream['request'], int) \
                    and stream['mitmproxy_flow'] is None:
                http_flow = self._create_mitmproxy_flow(flow, session, frame.stream_id)

                for addon in self.addons:
                    try:
                        if hasattr(addon, 'request'):
                            addon.request(http_flow)
                    except Exception as e:
                        logging.getLogger().exception("Addon error: %s", e)
            elif stream['n_ends'] == 2 \
                    or (stream['n_ends'] == 1 and isinstance(stream['request'], int)):
                if stream['mitmproxy_flow'] is None:
                    http_flow = self._create_mitmproxy_flow(flow, session, frame.stream_id)
                self._add_mitmproxy_response(session, frame.stream_id)

                http_flow: http.HTTPFlow = stream['mitmproxy_flow']
                if self.dumper:
                    self.dumper.echo_flow(http_flow)

                for addon in self.addons:
                    try:
                        if hasattr(addon, 'response'):
                            addon.response(http_flow)
                    except Exception as e:
                        logging.getLogger().exception("Addon error: %s", e)

    def tcp_end(self, flow: tcp.TCPFlow):
        skey = self._get_sessions_key(flow.client_conn.peername, flow.server_conn.peername)
        del self._sessions[skey]

    def tcp_error(self, flow: tcp.TCPFlow):
        skey = self._get_sessions_key(flow.client_conn.peername, flow.server_conn.peername)
        del self._sessions[skey]


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

    This addon intercepts TCP data, converts them into network packets, and stores them for later 
    export as a PCAP file.
    """

    containers: dict[str, ContainerInfo]
    """A dictionary mapping container names to their respective `ContainerInfo` objects, which include network details."""

    packets: list[Packet]
    """A list to store the captured network packets."""

    def __init__(self, containers: dict[str, ContainerInfo]):
        self.containers = containers
        self.packets = []
        self._sessions: dict[str, dict[str, Any]] = {}

    def _get_sessions_key(self, client: tuple[str, int], server: tuple[str, int]) -> Any:
        """Get a session key to use for the client-server pair specified.

        Args:
            client: A tuple containing the client IP address and port.
            server: A tuple containing the server IP address and port.

        Returns:
            Any: The session key.
        """

        return (client[0], client[1], server[0], server[1])

    def _add_packet(self, session: dict[str, Any], from_client: bool, content: bytes):
        """Add a network packet to the list of captured packets.

        This function constructs a network packet using the provided source and destination
        addresses and content, then appends it to the internal list of packets. It also manages
        the sequence number for the packet to ensure correct ordering.

        Args:
            src: A tuple containing the source IP address and port.
            dst: A tuple containing the destination IP address and port.
            content: The content of the packet to be added.
        """

        if from_client:
            src = session['client']
            dst = session['server']
        else:
            src = session['server']
            dst = session['client']

        if dst['seq'] != src['ack']:
            ack = src['ack'] = dst['seq']
        else:
            ack = None

        l2 = Ether()
        l3 = IP(src=src['ip'], dst=dst['ip'])
        l4 = TCP(sport=src['port'], dport=dst['port'], flags=0, seq=src['seq'], ack=ack)
        packet = l2 / l3 / l4 / content
        self.packets.append(packet)
        src['seq'] = (src['seq'] + len(content)) % 2**32

    def tcp_start(self, flow: tcp.TCPFlow):
        skey = self._get_sessions_key(flow.client_conn.peername, flow.server_conn.peername)
        self._sessions[skey] = {
            'server': {
                'ip': flow.server_conn.peername[0],
                'port': flow.server_conn.peername[1],
                'seq': 1,
                'ack': 1
            },
            'client': {
                'ip': flow.client_conn.peername[0],
                'port': flow.client_conn.peername[1],
                'seq': 1,
                'ack': 1
            }
        }

    def tcp_message(self, flow: tcp.TCPFlow):
        skey = self._get_sessions_key(flow.client_conn.peername, flow.server_conn.peername)
        session = self._sessions[skey]
        msg = flow.messages[-1]
        self._add_packet(session, msg.from_client, msg.content)

    def tcp_end(self, flow: tcp.TCPFlow):
        skey = self._get_sessions_key(flow.client_conn.peername, flow.server_conn.peername)
        del self._sessions[skey]

    def tcp_error(self, flow: tcp.TCPFlow):
        skey = self._get_sessions_key(flow.client_conn.peername, flow.server_conn.peername)
        del self._sessions[skey]

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

        self._user_addons = []
        self.add_addons(*user_addons)

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

        dumper: Dumper = self._master.addons.get('Dumper'.lower())
        for addon in addons:
            if hasattr(addon, 'dumper'):
                setattr(addon, 'dumper', dumper)

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
            self._master.addons.remove(addon)
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
                - `'certs_path'` (optional): The path of a directory containing all the TLS 
                        certificates that will be used. Each certificate must be in pem format, and 
                        its name must be the name of the network function whose certificate belongs 
                        to. If not provided, no TLS connection will be analyzed. No value is 
                        provided as default.
                - `'exclude'` (optional): A list of strings representing the names of the 
                        containers that will be excluded from the monitoring process.
                - `'proxy_port'` (optional): An integer representing the TCP port on which the 
                        monitor will work. Defaults to `8080`.
                - `'openapi_path'` (optional): The path of a directory containing all the OpenAPI 
                        specification files on which NFs' requests and responses will be checked. 
                        If not provided, the adherence to the OpenAPI specification will be 
                        skipped. No value is provided as default.
                - `'restart_on_epoch'` (optional): Whether the proxy should be started and stopped 
                        respectively at the beginning and at the end of every epoch. Defaults to 
                        `False`.
                - `'restart_on_test'` (optional): Whether the proxy should be started and stopped 
                        respectively at the beginning and at the end of every test case or not. 
                        Defaults to `False`.
                - `'restart_on_redo'` (optional): Whether the proxy should be restarted before 
                        re-performing a test case or not. Defaults to `False`.
                - `'restart_on_fault'` (optional): Whether the proxy should be restarted at the end 
                        of a test case after a fault has been found or not (even if 
                        `restart_on_test` is set to `False`). Defaults to `False`.

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

                # if pem_cert.startswith(b'-----BEGIN CERTIFICATE-----') \
                #        and pem_cert.endswith(b'-----END CERTIFICATE-----\n'):
                #    c = Cert.from_pem(pem_cert)
                #    self.certs[p.name] = c
                #    logging.getLogger().warning('Loaded certificate at %s', p)
                # else:
                #    logging.getLogger().warning('Invalid certificate at %s', p)

                if b'-----BEGIN CERTIFICATE-----' in pem_cert \
                        and b'-----END CERTIFICATE-----' in pem_cert:
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
                except Exception:
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
        'proxy_port': 8080,
        'openapi_path': None,
        'restart_on_epoch': False,
        'restart_on_test': False,
        'restart_on_redo': False,
        'restart_on_fault': False
    }

    options: dict[str, str | Path | list[str] | int | None]
    """Options currently set on the agent."""

    def __init__(self, **kwargs):
        super().__init__(None, **kwargs)

        self.options = dict(self.DEFAULT_OPTIONS)
        self.set_options(**kwargs)

        self._is_iptable_cleaned: bool = True
        self._proxy: ThreadedMitmProxy | None = None
        self._network_ip: str = ''
        self._iface_name: str = ''
        self._network_name: str = ''
        self._address_getters: list[ContainerAddressGetter] = []
        self._tls_cert_loader: TlsCertLoader | None = None
        self._openapi_specs_loader: OpenAPISpecsLoader | None = None
        self._pcap_exporter: PCAPExportAddon | None = None
        self._openapi_checker: OpenAPICheckerAddon | None = None
        self._fault_detected: bool = False
        self._is_running: bool = False

    @override
    def set_options(self, **kwargs):
        for key, val in kwargs.items():
            if key not in self.options:
                continue

            if key == 'compose_yaml_path':
                val = Path(kwargs[key])

            elif key == 'certs_path':
                val = Path(kwargs[key])
                if self._tls_cert_loader is not None:
                    self._tls_cert_loader.join()
                self._tls_cert_loader = TlsCertLoader(val)
                self._tls_cert_loader.start()

            elif key == 'openapi_path':
                val = Path(kwargs[key])
                if self._openapi_specs_loader is not None:
                    self._openapi_specs_loader.join()
                self._openapi_specs_loader = OpenAPISpecsLoader(val)
                self._openapi_specs_loader.start()

            self.options[key] = val
            logging.info('Set %s = %s', key, val)

    @override
    def reset(self):
        if not self._is_iptable_cleaned:
            self._remove_iptable_rule(self._iface_name, self._network_ip, self.options['proxy_port'])
        self._pause_mitmproxy()
        self.options = dict(self.DEFAULT_OPTIONS)
        self._network_ip = ''
        self._iface_name = ''
        self._network_name = ''
        self._address_getters = []
        self._tls_cert_loader = None
        self._openapi_specs_loader = None
        self._pcap_exporter = None
        self._openapi_checker = None
        self._fault_detected = False
        self._is_running = False

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

        self._is_iptable_cleaned = False

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
                    self._is_iptable_cleaned = True
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

            if 'networks' in container_config and isinstance(container_config['networks'], dict):
                for network_name, network_config in container_config['networks'].items():
                    if network_name == self.options['network_name'] and network_config is not None:
                        for alias in network_config.get('aliases', []):
                            aliases[alias] = container_name
                        break
        return aliases

    def _get_network_data_from_configs(self, configs: dict, environ: dict[str, str]) -> tuple[str, str, str]:
        """Extract network-related data from the provided configuration dictionary.

        This function retrieves the network IP, interface name, and network name from the given 
        configuration dictionary. It uses the network name specified in the agent's options to 
        locate the correct network configuration.

        Args:
            configs: A dictionary containing the parsed configuration data, typically from a 
                docker-compose.yaml file.
            environ: A dictionary containing the environment variables.

        Returns:
            tuple[str, str, str]: A tuple containing three strings:
                1. The subnet IP address of the network.
                2. The name of the network interface.
                3. The name of the network.

        Raises:
            AgentError: If the specified network is not found in the configuration, if no IP 
                address is found for the network, or if no interface name is found for the network.
        """

        var_pattern = re.compile(r'\${(\w+)}')

        def replace_match(match):
            var_name = match.group(1)
            return environ.get(var_name, match.group(0))

        try:
            network = configs['networks'][self.options['network_name']]
        except KeyError as e:
            msg = f"No network named '{self.options['network_name']}' found in {self.options['compose_yaml_path']}"
            logging.getLogger().error(msg)
            raise AgentError(msg) from e

        try:
            for c in network['ipam']['config']:
                if 'subnet' in c:
                    network_ip = var_pattern.sub(replace_match, c['subnet'])
                    break
            else:
                raise KeyError()
        except KeyError as e:
            msg = "No IP address found for network named " \
                + f"'{self.options['network_name']}' in {self.options['compose_yaml_path']}"
            logging.getLogger().error(msg)
            raise AgentError(msg) from e

        try:
            iface_name = var_pattern.sub(replace_match, network['driver_opts']['com.docker.network.bridge.name'])
        except KeyError as e:
            msg = "No interface name found for network named " \
                + f"'{self.options['network_name']}' in {self.options['compose_yaml_path']}"
            logging.getLogger().error(msg)
            raise AgentError(msg) from e

        if 'name' in network:
            network_name = var_pattern.sub(replace_match, network['name'])
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

        addons = [IgnoreClientConnectionAddon()]

        http2_overlay = Http2OverlayAddon()
        self._pcap_exporter = PCAPExportAddon(containers)

        if self.options['certs_path'] is not None:
            addons.append(TLSCustomCertAddon(containers))

        addons.append(self._pcap_exporter)

        if self.options['openapi_path'] is not None:
            self._openapi_checker = OpenAPICheckerAddon(containers, aliases)
            http2_overlay.addons.append(self._openapi_checker)

        addons.append(http2_overlay)

        self._proxy = ThreadedMitmProxy(
            addons,
            mode=['transparent'],
            listen_port=self.options['proxy_port'],
            ignore_hosts=[],
            tcp_hosts=[".*"],
            show_ignored_hosts=False,
            ssl_insecure=True,
            dumper_filter="!~tcp"
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

        addons = [IgnoreClientConnectionAddon()]

        http2_overlay = Http2OverlayAddon()
        self._pcap_exporter = PCAPExportAddon(containers)

        if self.options['certs_path'] is not None:
            addons.append(TLSCustomCertAddon(containers))

        addons.append(self._pcap_exporter)

        if self.options['openapi_path'] is not None:
            self._openapi_checker = OpenAPICheckerAddon(containers, aliases)
            http2_overlay.addons.append(self._openapi_checker)

        addons.append(http2_overlay)

        self._proxy.add_addons(*addons)
        self._proxy.update_options(
            mode=['transparent'],
            listen_port=self.options['proxy_port'],
            ignore_hosts=[],
            tcp_hosts=[".*"],
            show_ignored_hosts=False,
            ssl_insecure=True,
            dumper_filter="!~tcp"
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

    def _start_procedure(self):
        """Initialize and start the network proxy.

        This method sets up the network proxy by:
        1. Loading the docker-compose configuration.
        2. Extracting network and container information.
        3. Starting the mitmproxy instance with the configured addons.
        4. Configuring iptables rules for traffic redirection.

        Raises:
            AgentError: If:
                - Any of the required options is not set.
                - There is an error loading the docker-compose configuration.
                - The network specified through the options is not found in the configuration.
                - No IP address or interface name is found for the network specified.
        """

        if self.options['compose_yaml_path'] is None:
            msg = "No docker-compose.yaml path specified"
            logging.getLogger().error(msg)
            raise AgentError(msg)

        if self.options['network_name'] is None:
            msg = "No network name specified"
            logging.getLogger().error(msg)
            raise AgentError(msg)

        try:
            with open(self.options['compose_yaml_path'], 'r', encoding='utf8') as f:
                compose_configs = yaml.safe_load(f)
        except yaml.YAMLError as e:
            msg = f"Error loading {self.options['compose_yaml_path']}: {e}"
            logging.getLogger().error(msg)
            raise AgentError(msg) from e

        environ = {**os.environ}
        dotenv_path = self.options['compose_yaml_path'].parent / ".env"
        if dotenv_path.exists():
            environ.update(dotenv_values(dotenv_path))

        data = self._get_network_data_from_configs(compose_configs, environ)
        self._network_ip, self._iface_name, self._network_name = data
        aliases = self._get_container_aliases(compose_configs)

        containers: dict[str, ContainerInfo] = {}
        for container_config in compose_configs['services'].values():
            container_name = container_config['container_name']

            while (self._tls_cert_loader and self._tls_cert_loader.is_alive()) \
                    or (self._openapi_specs_loader and self._openapi_specs_loader.is_alive()):
                time.sleep(0.5)

            cert = None
            if self.options['certs_path'] is not None:
                for p, cert in self._tls_cert_loader.certs.items():
                    if container_name in p:
                        break

            specs = []
            if self.options['openapi_path'] is not None:
                for name, s in self._openapi_specs_loader.specs.items():
                    if name.split('_')[1][1:] == container_name:
                        specs.append(s)

            info = ContainerInfo(container_name, cert=cert, specs=specs)
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

    def _stop_procedure(self, pause_only: bool = True):
        """Stop or pause the network proxy.

        This method stops or pauses the network proxy by removing iptables rules for traffic 
        redirection (if needed) and stopping or pausing the mitmproxy instance

        Args:
            pause_only (optional): `True` if the mitmproxy instance should be paused instead of 
                being fully stopped. Defaults to `True`.

        Raises:
            AgentError: If an error occurs while removing iptables rules.
        """

        if not self._is_iptable_cleaned:
            self._remove_iptable_rule(self._iface_name, self._network_ip, self.options['proxy_port'])
            self._is_iptable_cleaned = True

        if pause_only:
            self._pause_mitmproxy()
        else:
            self._stop_mitmproxy()

        for getter in self._address_getters:
            getter.join()

        self._address_getters = []

    @override
    def on_epoch_start(self, ctx: ExecutionContext):
        if self.options['restart_on_epoch'] and not self._is_running:
            self._start_procedure()
            self._is_running = True

    @override
    def on_epoch_end(self):
        if self.options['restart_on_epoch']:
            self._stop_procedure()
            self._is_running = False

    @override
    def on_test_start(self, ctx: ExecutionContext):
        if (self.options['restart_on_test'] or self._fault_detected) and not self._is_running:
            self._fault_detected = False
            self._start_procedure()
            self._is_running = True

    @override
    def on_test_end(self):
        if self.options['restart_on_test'] or self._fault_detected:
            self._stop_procedure()
            self._is_running = False

    @override
    def on_redo(self):
        if self.options['restart_on_redo']:
            self._stop_procedure()
            self._start_procedure()

    @override
    def fault_detected(self) -> bool:
        if self._openapi_checker is None:
            return False

        return self._openapi_checker.error is not None

    @override
    def on_fault(self):
        self._fault_detected = self.options['restart_on_fault']

    @override
    def get_data(self) -> list[tuple[str, bytes]]:
        if self._pcap_exporter is None:
            return []

        return [('dump.pcap', self._pcap_exporter.export())]

    @override
    def on_shutdown(self):
        self._stop_procedure(pause_only=False)


__all__ = ['NetworkFunctionProxyAgent']


def main():
    parser = argparse.ArgumentParser(
        description='Agent that controls a network proxy specifically crafted for network functions.')
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
