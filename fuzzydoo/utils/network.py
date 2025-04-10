import subprocess
from threading import RLock
from typing import Any, Iterable, Sequence

from pycrate_core.elt import Element
from pycrate_asn1rt.asnobj import ASN1Obj


def nas_disable_safety_checks(obj: Element) -> None:
    """Disables the NAS checks for a given element.

    Args:
        obj: The element for which to disable NAS checks.
    """

    # pylint: disable=protected-access
    obj._SAFE_STAT = False
    obj._SAFE_DYN = False


PYCRATE_NGAP_STRUCT_LOCK: RLock = RLock()
"""Thread lock reserved for pycrate's NGAP structures, which are not thread-safe (unlike NAS 
structures). See [this](https://github.com/pycrate-org/pycrate/wiki/Compiling-asn1-specifications#limitations)."""


def ngap_modify_safety_checks(msg: ASN1Obj, path: Sequence, enable: bool) -> None:
    """Modify the NGAP checks for a given ASN.1 object.

    Note: This function modify the checks for all the objects in the path.

    Args:
        msg: The ASN.1 message for which to modify NGAP checks.
        path: The path to the ASN.1 object within `msg` whose checks will be modified.
        enable: Whether to enable or disable the checks for the path.
    """

    with PYCRATE_NGAP_STRUCT_LOCK:
        n = len(path)
        while n >= 0:
            obj = msg.get_at(path[:n])

            # pylint: disable=protected-access
            obj._SILENT = not enable
            obj._SAFE_STAT = enable
            obj._SAFE_DYN = enable
            obj._SAFE_INIT = enable
            obj._SAFE_VAL = enable
            obj._SAFE_BND = enable
            obj._SAFE_BNDTAB = enable

            n -= 1


def ngap_to_aper_unsafe(msg: ASN1Obj, modified_paths: Iterable[Sequence]) -> bytes:
    """Converts an NGAP ASN.1 message to APER without safety checks.

    Args:
        msg: The NGAP ASN.1 message to convert.
        modified_paths: The paths of elements that have been modified.

    Returns:
        The APER encoded bytes of the NGAP message.
    """

    with PYCRATE_NGAP_STRUCT_LOCK:
        constraints: dict[tuple, dict[str, Any]] = {}
        for path in modified_paths:
            backup_constraints = {}
            modded_obj = msg.get_at(path)
            const_keys = list(modded_obj.get_const().keys())
            for key in const_keys:
                key = '_const_' + key
                backup_constraints[key] = getattr(modded_obj, key)
                setattr(modded_obj, key, None)
            constraints[tuple(path)] = backup_constraints

        result: bytes = msg.to_aper()

        for path, backup_constraints in constraints.items():
            modded_obj = msg.get_at(path)
            for key, value in backup_constraints.items():
                setattr(modded_obj, key, value)

        return result


def container_to_addresses(container_name: str, network_name: str) -> tuple[str, str] | None:
    """Retrieves the IP and MAC addresses of a Docker container within a specified network.

    Args:
        container_name: The name of the Docker container.
        network_name: The name of the Docker network.

    Returns:
        tuple[str, str] | None: A tuple containing the IP address and MAC address of the container 
            if found, otherwise `None`.
    """

    ip_filter = '{{with index .NetworkSettings.Networks ' + f'"{network_name}"' \
        + '}}{{.IPAddress}} {{.MacAddress}}{{end}}'
    try:
        inspect_cmd = subprocess.run(
            args=['docker', 'inspect', '-f', ip_filter, container_name],
            check=True, capture_output=True, encoding='utf8')
    except subprocess.CalledProcessError:
        return None

    if addresses := inspect_cmd.stdout.strip():
        addresses = addresses.split()
        if len(addresses) == 2:
            return tuple(addresses)
    return None


def ip_to_container(ip: str, network_name: str) -> str | None:
    """Retrieves the name of a Docker container based on its IP address within a specified network.

    Args:
        ip: The IP address of the Docker container.
        network_name: The name of the Docker network to search within.

    Returns:
        str | None: The name of the container if found, otherwise `None`.
    """

    name_filter = '{{range .Containers}}{{if eq .IPv4Address "' + ip \
        + '"}}{{.Name}}{{end}}{{end}}'
    try:
        inspect_cmd = subprocess.run(
            args=['docker', 'network', 'inspect', '-f', name_filter, network_name],
            check=True, capture_output=True, encoding='utf8')
    except subprocess.CalledProcessError:
        return None

    if name := inspect_cmd.stdout.strip():
        return name
    return None
