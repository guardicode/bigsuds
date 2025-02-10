#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An iControl client library (Python 3.12 version).

See the documentation for the BIGIP class for usage examples.
"""

from urllib.error import URLError
from http.client import BadStatusLine
from urllib.request import build_opener, HTTPBasicAuthHandler, HTTPSHandler

import logging
import os
import re
import ssl
from xml.sax import SAXParseException

import suds.client
from suds.cache import ObjectCache
from suds.sudsobject import Object as SudsObject
from suds.client import Client
from suds.xsd.doctor import ImportDoctor, Import
from suds.transport import TransportError
from suds.transport.https import HttpAuthenticated
from suds import WebFault, TypeNotFound, MethodNotFound as _MethodNotFound


__version__ = '1.3.12'


# We need to monkey-patch the Client's ObjectCache due to a suds bug:
# https://fedorahosted.org/suds/ticket/376
suds.client.ObjectCache = lambda **kwargs: None


class HTTPSHandlerNoVerify(HTTPSHandler):
    """
    A custom HTTPS handler that disables certificate verification.
    """
    def __init__(self, *args, **kwargs):
        # For Python 3.7+, _create_unverified_context is always available.
        kwargs['context'] = ssl._create_unverified_context()
        super().__init__(*args, **kwargs)


class HTTPSTransportNoVerify(HttpAuthenticated):
    """
    A custom HTTPS transport that uses the above HTTPSHandlerNoVerify.
    """
    def u2handlers(self):
        handlers = super().u2handlers()
        handlers.append(HTTPSHandlerNoVerify())
        return handlers


log = logging.getLogger('bigsuds')


class OperationFailed(Exception):
    """Base class for bigsuds exceptions."""


class ServerError(OperationFailed, WebFault):
    """Raised when the BIGIP returns an error via the iControl interface."""


class ConnectionError(OperationFailed):
    """Raised when the connection to the BIGIP fails."""


class ParseError(OperationFailed):
    """
    Raised when parsing data from the BIGIP as a SOAP message fails.

    Also raised when an invalid iControl namespace is looked up (e.g. bigip.LocalLB.Bad).
    """


class MethodNotFound(OperationFailed, _MethodNotFound):
    """Raised when a particular iControl method does not exist."""


class ArgumentError(OperationFailed):
    """
    Raised when too many arguments or incorrect keyword arguments
    are passed to an iControl method.
    """


class BIGIP:
    """
    This class exposes the BIGIP's iControl interface.

    Example usage:
        >>> b = BIGIP('bigip-hostname')
        >>> print(b.LocalLB.Pool.get_list())
        ['/Common/test_pool']
        >>> b.LocalLB.Pool.add_member(['/Common/test_pool'],
        ...     [[{'address': '10.10.10.10', 'port': 20030}]])
        >>> print(b.LocalLB.Pool.get_member(['/Common/test_pool']))
        [[{'port': 20020, 'address': '10.10.10.10'},
          {'port': 20030, 'address': '10.10.10.10'}]]

    Some notes on Exceptions:
      - The looking up of iControl namespaces on the BIGIP instance can
        raise ParseError and ServerError.
      - The looking up of an iControl method can raise MethodNotFound.
      - Calling an iControl method can raise ServerError, ConnectionError,
        MethodNotFound, ParseError, or ArgumentError.
      - All derive from OperationFailed.
    """

    def __init__(self, hostname, username='admin', password='admin',
                 debug=False, cachedir=None, verify=False, timeout=90,
                 port=443):
        """
        @param hostname: The IP or hostname of the BIGIP.
        @param username: The admin username on the BIGIP.
        @param password: The admin password on the BIGIP.
        @param debug: When True, enable doc introspection/tab-completion.
        @param cachedir: Directory to cache WSDLs (None disables caching).
        @param verify: When True, perform SSL cert validation if supported.
        @param timeout: Connection timeout in seconds.
        @param port: Port for iControl (usually 443).
        """
        self._hostname = hostname
        self._port = port
        self._username = username
        self._password = password
        self._debug = debug
        self._cachedir = cachedir
        self._verify = verify
        self._timeout = timeout
        if debug:
            self._instantiate_namespaces()

    def with_session_id(self, session_id=None):
        """
        Returns a new instance of BIGIP using a unique session id.

        @param session_id: If None, a new one is requested from the BIGIP.
        """
        if session_id is None:
            session_id = self.System.Session.get_session_identifier()
        return _BIGIPSession(
            self._hostname, session_id,
            self._username, self._password,
            self._debug, self._cachedir,
            self._verify, self._timeout, self._port
        )

    def __getattr__(self, attr):
        # e.g. bigip.LocalLB, bigip.System
        if attr.startswith('__'):
            return super().__getattribute__(attr)
        if '_' in attr:
            # For backwards compat with pycontrol: bigip.LocalLB_Pool
            first, second = attr.split('_', 1)
            return getattr(getattr(self, first), second)
        ns = _Namespace(attr, self._create_client)
        setattr(self, attr, ns)
        return ns

    def _create_client(self, wsdl_name):
        try:
            client = get_client(
                self._hostname, wsdl_name,
                self._username, self._password,
                self._cachedir, self._verify,
                self._timeout, self._port
            )
        except SAXParseException as e:
            raise ParseError(
                f'{e}\nFailed to parse WSDL. Is "{wsdl_name}" a valid namespace?'
            )
        except (URLError, TransportError) as e:
            # e.g. invalid credentials → TransportError
            raise ConnectionError(str(e))
        return self._create_client_wrapper(client, wsdl_name)

    def _create_client_wrapper(self, client, wsdl_name):
        return _ClientWrapper(
            client,
            self._arg_processor_factory,
            _NativeResultProcessor,
            wsdl_name,
            self._debug
        )

    def _arg_processor_factory(self, client, method):
        return _DefaultArgProcessor(method, client.factory)

    def _instantiate_namespaces(self):
        wsdls = get_wsdls(
            self._hostname, self._username, self._password,
            self._verify, self._timeout, self._port
        )
        for namespace, attr_list in wsdls.items():
            ns = getattr(self, namespace)
            ns.set_attr_list(attr_list)


class Transaction:
    """
    A context manager for iControl transactions (BIGIP v11+).

    Commits on success, rolls back on exception.
    """

    def __init__(self, bigip):
        self.bigip = bigip

    def __enter__(self):
        self.bigip.System.Session.start_transaction()
        return self.bigip

    def __exit__(self, exc_type, exc_value, exc_tb):
        if exc_tb is None:
            self.bigip.System.Session.submit_transaction()
        else:
            try:
                self.bigip.System.Session.rollback_transaction()
            except ServerError:
                pass


def get_client(hostname, wsdl_name, username='admin', password='admin',
               cachedir=None, verify=False, timeout=90, port=443):
    """
    Returns a suds.client.Client for a given iControl WSDL.

    Raises URLError, TransportError, SAXParseException on connection/parsing issues.
    """
    url = f'https://{hostname}:{port}/iControl/iControlPortal.cgi?WSDL={wsdl_name}'
    imp = Import('http://schemas.xmlsoap.org/soap/encoding/')
    imp.filter.add('urn:iControl')

    cache_obj = None
    if cachedir is not None:
        cache_obj = ObjectCache(location=os.path.expanduser(cachedir), days=1)

    doctor = ImportDoctor(imp)
    if verify:
        # If your Python environment supports SSL validation
        client = Client(
            url, doctor=doctor,
            username=username, password=password,
            cache=cache_obj, timeout=timeout
        )
    else:
        transport = HTTPSTransportNoVerify(
            username=username, password=password, timeout=timeout
        )
        client = Client(
            url, doctor=doctor,
            username=username, password=password,
            cache=cache_obj, transport=transport,
            timeout=timeout
        )

    # Force subsequent requests to keep using the same base URL
    client.set_options(location=url.split('?')[0])
    client.factory.separator('_')
    return client


def get_wsdls(hostname, username='admin', password='admin',
              verify=False, timeout=90, port=443):
    """
    Returns a dict of all available WSDLs on this server:
        e.g. { 'LocalLB': ['Pool','NodeAddress'], 'System': [...] }
    """
    url = f'https://{hostname}:{port}/iControl/iControlPortal.cgi'
    regex = re.compile(r'/iControl/iControlPortal.cgi\?WSDL=([^"]+)"')

    auth_handler = HTTPBasicAuthHandler()
    auth_handler.add_password(
        realm="BIG-IP",
        uri=f'https://{hostname}:{port}/',
        user=username,
        passwd=password
    )
    auth_handler.add_password(
        realm="BIG\-IP",
        uri=f'https://{hostname}:{port}/',
        user=username,
        passwd=password
    )

    if verify:
        opener = build_opener(auth_handler)
    else:
        opener = build_opener(auth_handler, HTTPSHandlerNoVerify())

    try:
        result = opener.open(url, timeout=timeout)
    except URLError as e:
        raise ConnectionError(str(e))

    wsdls = {}
    for line in result.readlines():
        match = regex.search(line.decode(errors='ignore'))
        if match:
            full = match.groups()[0]
            # Typically something like "LocalLB.Pool" => split into (LocalLB, Pool)
            namespace, rest = full.split('.', 1)
            wsdls.setdefault(namespace, []).append(rest)
    return wsdls


class _BIGIPSession(BIGIP):
    """
    A BIGIP subclass that attaches 'X-iControl-Session' headers to all requests.
    """

    def __init__(self, hostname, session_id, username='admin', password='admin',
                 debug=False, cachedir=None, verify=False, timeout=90, port=443):
        super().__init__(
            hostname, username=username, password=password,
            debug=debug, cachedir=cachedir,
            verify=verify, timeout=timeout, port=port
        )
        self._headers = {'X-iControl-Session': str(session_id)}

    def _create_client_wrapper(self, client, wsdl_name):
        client.set_options(headers=self._headers)
        return super()._create_client_wrapper(client, wsdl_name)


class _Namespace:
    """
    Represents an iControl namespace (e.g. "LocalLB").
    """

    def __init__(self, name, client_creator):
        self._name = name
        self._client_creator = client_creator
        self._attrs = []

    def __dir__(self):
        return sorted(set(dir(type(self)) + list(self.__dict__) + self._attrs))

    def __getattr__(self, attr):
        if attr.startswith('__'):
            return super().__getattribute__(attr)
        client = self._client_creator(f'{self._name}.{attr}')
        setattr(self, attr, client)
        return client

    def set_attr_list(self, attr_list):
        self._attrs = attr_list


class _ClientWrapper:
    """
    A wrapper class that extends a suds.client.Client with argument/result processing.
    """

    def __init__(self, client, arg_processor_factory, result_processor_factory,
                 wsdl_name, debug=False):
        self._client = client
        self._arg_factory = arg_processor_factory
        self._result_factory = result_processor_factory
        self._wsdl_name = wsdl_name
        self._usage = {}

        if debug:
            binding_el = client.wsdl.services[0].ports[0].binding[0]
            for op in binding_el.getChildren("operation"):
                usage = None
                doc = op.getChild("documentation")
                if doc is not None:
                    usage = doc.getText().strip()
                self._usage[op.get("name")] = usage

            # Force method creation for tab-completion
            for method in client.sd[0].ports[0][1]:
                getattr(self, method[0])

    def __getattr__(self, attr):
        # Attempt to retrieve the corresponding suds method
        try:
            method = getattr(self._client.service, attr)
        except _MethodNotFound as e:
            e.__class__ = MethodNotFound
            raise

        usage = self._usage.get(attr, None)
        wrapped = _wrap_method(
            method,
            self._wsdl_name,
            self._arg_factory(self._client, method),
            self._result_factory(),
            usage
        )
        setattr(self, attr, wrapped)
        return wrapped

    def __str__(self):
        # Return the client’s raw WSDL definition
        return str(self._client)


def _wrap_method(method, wsdl_name, arg_processor, result_processor, usage):
    """Wrap a suds method to handle argument/result processing."""
    icontrol_sig = f"iControl signature: {_method_string(method)}"

    if usage:
        usage += f"\n\n{icontrol_sig}"
    else:
        usage = f"Wrapper for {wsdl_name}.{method.method.name}\n\n{icontrol_sig}"

    def wrapped_method(*args, **kwargs):
        log.debug(
            'Executing iControl method: %s.%s(%s, %s)',
            wsdl_name, method.method.name, args, kwargs
        )
        args, kwargs = arg_processor.process(args, kwargs)
        try:
            result = method(*args, **kwargs)
        except AttributeError:
            raise ConnectionError("iControl call failed (possibly invalid credentials).")
        except _MethodNotFound as e:
            e.__class__ = MethodNotFound
            raise
        except WebFault as e:
            e.__class__ = ServerError
            raise
        except URLError as e:
            raise ConnectionError(f"URLError: {e}")
        except BadStatusLine as e:
            raise ConnectionError(f"BadStatusLine: {e}")
        except SAXParseException:
            raise ParseError("Failed to parse the BIGIP's response (likely a 500 error).")
        return result_processor.process(result)

    wrapped_method.__doc__ = usage
    wrapped_method.__name__ = str(method.method.name)
    wrapped_method._method = method  # so advanced users can introspect
    return wrapped_method


class _ArgProcessor:
    """Base class for argument processing before SOAP calls."""

    def process(self, args, kwargs):
        raise NotImplementedError("process() must be overridden.")


class _DefaultArgProcessor(_ArgProcessor):
    """
    ArgProcessor that converts standard Python types (dict, list, etc.)
    into SudsObjects for iControl calls.
    """

    def __init__(self, method, factory):
        self._factory = factory
        self._method = method
        self._argspec = self._make_argspec(method)

    def _make_argspec(self, method):
        # Return a list of (param_name, param_type_string)
        spec = []
        for part in method.method.soap.input.body.parts:
            spec.append((part.name, part.type[0]))
        return spec

    def process(self, args, kwargs):
        return self._process_args(args), self._process_kwargs(kwargs)

    def _process_args(self, args):
        newargs = []
        for i, arg in enumerate(args):
            try:
                argtype = self._argspec[i][1]
            except IndexError:
                raise ArgumentError(
                    f"Too many arguments passed to method: {_method_string(self._method)}"
                )
            newargs.append(self._process_arg(argtype, arg))
        return newargs

    def _process_kwargs(self, kwargs):
        newkwargs = {}
        for name, value in kwargs.items():
            matches = [x for x in self._argspec if x[0] == name]
            if not matches:
                raise ArgumentError(
                    f'Invalid keyword argument "{name}" for method: {_method_string(self._method)}'
                )
            argtype = matches[0][1]
            newkwargs[name] = self._process_arg(argtype, value)
        return newkwargs

    def _process_arg(self, arg_type, value):
        if isinstance(value, SudsObject):
            return value

        if '.' not in arg_type and ':' not in arg_type:
            # Not a SOAP namespace type, pass raw
            return value

        try:
            obj = self._factory.create(arg_type)
        except TypeNotFound:
            log.error("Failed to create type: %s", arg_type)
            return value

        # If user passes dict, map to attributes
        if isinstance(value, dict):
            for k, subval in value.items():
                if not hasattr(obj, k):
                    valid_attrs = ', '.join(x[0] for x in obj)
                    raise ArgumentError(
                        f'"{k}" is not a valid attribute for {obj.__class__.__name__}; expected: {valid_attrs}'
                    )
                sub_class_name = getattr(obj, k).__class__.__name__
                setattr(obj, k, self._process_arg(sub_class_name, subval))
            return obj

        # If array type, fill obj.items = [...]
        array_type = self._array_type(obj)
        if array_type is not None:
            if isinstance(value, str):
                raise ArgumentError(
                    f'{obj.__class__.__name__} needs an iterable, but got a string "{value}"'
                )
            obj.items = [self._process_arg(array_type, x) for x in value]
            return obj

        # If no attributes and not an array → might be an enum
        if not obj:
            return value

        # If it's an enum, ensure the given value matches
        if value not in obj:
            valid_values = ', '.join(x[0] for x in obj)
            raise ArgumentError(
                f'"{value}" is not valid for {obj.__class__.__name__}; expecting: {valid_values}'
            )
        return value

    def _array_type(self, obj):
        try:
            attributes = obj.__metadata__.sxtype.attributes()
        except AttributeError:
            return None
        for each in attributes:
            if each[0].name == "arrayType":
                return getattr(each[0], "aty", [None])[0]
        return None


class _ResultProcessor:
    """Base class for processing the SOAP result."""

    def process(self, value):
        raise NotImplementedError("process() must be overridden.")


class _NativeResultProcessor(_ResultProcessor):
    """
    Converts SudsObjects to Python dicts/lists, etc.
    """

    def process(self, value):
        return self._convert_to_native_type(value)

    def _convert_to_native_type(self, value):
        # If a list, recurse
        if isinstance(value, list):
            return [self._convert_to_native_type(x) for x in value]
        elif isinstance(value, SudsObject):
            d = {}
            for attr_name, attr_val in value:
                d[attr_name] = self._convert_to_native_type(attr_val)
            return d
        elif isinstance(value, str):
            return value
        elif isinstance(value, int):
            return value
        # Else e.g. float/bool/None
        return value


def _method_string(method):
    """
    Return a SOAP signature string like: <methodName>(<type argName>, ...)
    """
    parts = []
    for part in method.method.soap.input.body.parts:
        parts.append(f"{part.type[0]} {part.name}")
    return f"{method.method.name}({', '.join(parts)})"
