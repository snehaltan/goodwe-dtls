"""Goodwe solar inverter communication library."""

from __future__ import annotations

import asyncio
import logging

from .const import GOODWE_UDP_PORT
from .dt import DT
from .es import ES
from .et import ET
from .exceptions import InverterError, RequestFailedException
from .inverter import EMSMode, Inverter, OperationMode, Sensor, SensorKind
from .model import DT_MODEL_TAGS, ES_MODEL_TAGS, ET_MODEL_TAGS
from .protocol import ProtocolCommand, UdpInverterProtocol, DtlsInverterProtocol, Aa55ProtocolCommand

logger = logging.getLogger(__name__)

# Inverter family names
ET_FAMILY = ["ET", "EH", "BT", "BH"]
ES_FAMILY = ["ES", "EM", "BP"]
DT_FAMILY = ["DT", "MS", "NS", "XS"]

# Initial discovery command (plain UDP / AA55 protocol)
DISCOVERY_COMMAND = Aa55ProtocolCommand("010200", "0182")

# Discovery packet sent to port 48899 to locate inverters on the network
_DISCOVERY_48899_PAYLOAD = "WIFIKIT-214028-READ"

# Response prefix from WiFi/LAN Kit 2.0 Cyber Security dongles
_DTLS_DONGLE_PREFIX = "dongle@sn"


def _parse_48899_response(raw: bytes) -> dict:
    """Parse UDP 48899 discovery response.

    Legacy dongles respond with:  '<IP>,<MAC>,<name>'
    Kit 2.0 Cyber Security dongles respond with: 'dongle@sn,dtls_port:<port>,<serial>'
    When busy with an active DTLS session: 'dongle@sn,dtls_port:<port>@busy,<serial>'

    Returns dict with keys: 'dtls' (bool), and either legacy or dtls fields.
    'busy' key is True when the dongle already has an active DTLS session.
    """
    try:
        text = raw.decode("utf-8").strip()
    except UnicodeDecodeError:
        return {"dtls": False, "raw": raw}

    if text.startswith(_DTLS_DONGLE_PREFIX):
        parts = text.split(",")
        dtls_port = GOODWE_UDP_PORT
        serial = ""
        busy = False
        for part in parts[1:]:
            if part.startswith("dtls_port:"):
                port_field = part.split(":")[1]
                if "@busy" in port_field:
                    busy = True
                    port_field = port_field.split("@")[0]
                try:
                    dtls_port = int(port_field)
                except ValueError:
                    pass
            else:
                serial = part
        return {"dtls": True, "busy": busy, "dtls_port": dtls_port, "serial": serial, "raw": text}

    # Legacy format: IP,MAC,name
    parts = text.split(",")
    return {
        "dtls": False,
        "ip": parts[0] if len(parts) > 0 else "",
        "mac": parts[1] if len(parts) > 1 else "",
        "name": parts[2] if len(parts) > 2 else "",
        "raw": text,
    }


def _inverter_from_serial(
    serial: str, host: str, port: int, comm_addr: int, timeout: int, retries: int,
    dtls: bool = False,
) -> Inverter | None:
    """Instantiate the right Inverter subclass based on serial number model tag."""
    def _make(cls):
        inv = cls(host, port, comm_addr, timeout, retries)
        if dtls:
            # Replace the plain UDP protocol with DTLS proxy protocol
            inv._protocol = DtlsInverterProtocol(host, port, comm_addr, timeout, retries)
        return inv

    for model_tag in ET_MODEL_TAGS:
        if model_tag in serial:
            logger.debug("Serial %s matches ET model tag '%s'.", serial, model_tag)
            return _make(ET)
    for model_tag in ES_MODEL_TAGS:
        if model_tag in serial:
            logger.debug("Serial %s matches ES model tag '%s'.", serial, model_tag)
            return _make(ES)
    for model_tag in DT_MODEL_TAGS:
        if model_tag in serial:
            logger.debug("Serial %s matches DT model tag '%s'.", serial, model_tag)
            return _make(DT)
    return None


async def _probe_48899(host: str, timeout: int = 3) -> dict | None:
    """Send discovery packet to port 48899 and parse the response.

    Retries when the dongle responds with @busy (active DTLS session in progress).
    Returns parsed dict on success, None on failure.
    """
    command = ProtocolCommand(_DISCOVERY_48899_PAYLOAD.encode("utf-8"), lambda r: True)
    for attempt in range(6):
        try:
            result = await command.execute(UdpInverterProtocol(host, 48899, timeout, 1))
            if result is not None:
                disc = _parse_48899_response(result.response_data())
                if disc.get("busy"):
                    logger.debug(
                        "Dongle at %s is busy with an existing DTLS session (attempt %d/6), "
                        "waiting 5s for it to release.",
                        host, attempt + 1,
                    )
                    await asyncio.sleep(5)
                    continue
                return disc
        except (InverterError, asyncio.CancelledError):
            pass
        break
    return None


async def connect(
    host: str,
    port: int = GOODWE_UDP_PORT,
    family: str = None,
    comm_addr: int = 0,
    timeout: int = 1,
    retries: int = 3,
    do_discover: bool = True,
) -> Inverter:
    """Contact the inverter at the specified host/port and answer appropriate Inverter instance.

    The specific inverter family/type will be detected automatically, but it can be passed explicitly.
    Supported inverter family names are ET, EH, BT, BH, ES, EM, BP, DT, MS, D-NS and XS.

    Inverter communication address may be explicitly passed, if not the usual default value
    will be used (0xf7 for ET/EH/BT/BH/ES/EM/BP inverters, 0x7f for DT/MS/D-NS/XS inverters).

    Since the UDP communication is by definition unreliable, when no (valid) response is received by the specified
    timeout, it is considered lost and the command will be re-tried up to retries times.

    Raise InverterError if unable to contact or recognise supported inverter.
    """
    if family in ET_FAMILY:
        inv = ET(host, port, comm_addr, timeout, retries)
    elif family in ES_FAMILY:
        inv = ES(host, port, comm_addr, timeout, retries)
    elif family in DT_FAMILY:
        inv = DT(host, port, comm_addr, timeout, retries)
    elif do_discover:
        return await discover(host, port, timeout, retries)
    else:
        raise InverterError("Specify either an inverter family or set do_discover True")

    # Probe 48899 even when family is known — dongle may require DTLS
    disc = await _probe_48899(host, timeout=max(timeout, 3))
    if disc and disc.get("dtls"):
        if not DtlsInverterProtocol.is_available():
            raise InverterError(
                "Inverter uses DTLS encryption (WiFi/LAN Kit 2.0) but 'socat' is not installed. "
                "Install socat (e.g. 'apt install socat' or 'brew install socat') and retry."
            )
        dtls_port = disc.get("dtls_port", port)
        dtls_timeout = max(timeout, 10)
        dtls_retries = max(retries, 5)
        inv._protocol = DtlsInverterProtocol(host, dtls_port, comm_addr, dtls_timeout, dtls_retries)
        logger.debug("Connecting to %s family inverter via DTLS at %s:%s.", family, host, dtls_port)
    else:
        logger.debug("Connecting to %s family inverter at %s:%s.", family, host, port)

    await inv.read_device_info()
    logger.debug("Connected to inverter %s, S/N:%s.", inv.model_name, inv.serial_number)
    return inv


async def discover(
    host: str, port: int = GOODWE_UDP_PORT, timeout: int = 1, retries: int = 3
) -> Inverter:
    """Contact the inverter at the specified value and answer appropriate Inverter instance.

    Automatically detects DTLS-encrypted dongles (WiFi/LAN Kit 2.0 Cyber Security)
    by probing port 48899 first. Falls back to plain UDP/TCP for older dongles.

    Raise InverterError if unable to contact or recognise supported inverter.
    """
    failures = []

    # --- DTLS detection via port 48899 ---
    disc = await _probe_48899(host, timeout=max(timeout, 3))
    if disc and disc.get("dtls"):
        if not DtlsInverterProtocol.is_available():
            raise InverterError(
                "Inverter uses DTLS encryption (WiFi/LAN Kit 2.0) but 'socat' is not installed. "
                "Install socat (e.g. 'apt install socat' or 'brew install socat') and retry."
            )
        dtls_port = disc.get("dtls_port", GOODWE_UDP_PORT)
        serial = disc.get("serial", "")
        logger.debug("Detected DTLS dongle at %s:%s (serial=%s).", host, dtls_port, serial)

        # Use a longer timeout for DTLS: first request triggers the handshake (~2-3s)
        dtls_timeout = max(timeout, 10)
        dtls_retries = max(retries, 5)

        inv = _inverter_from_serial(serial, host, dtls_port, 0, dtls_timeout, dtls_retries, dtls=True)
        if inv is not None:
            try:
                await inv.read_device_info()
                logger.debug("Connected to DTLS inverter %s, S/N:%s.", inv.model_name, inv.serial_number)
                return inv
            except InverterError as ex:
                failures.append(ex)

        # Serial didn't match any family — probe all ET/DT/ES with DTLS
        for cls in [ET, DT, ES]:
            i = cls(host, dtls_port, 0, dtls_timeout, dtls_retries)
            i._protocol = DtlsInverterProtocol(host, dtls_port, 0, dtls_timeout, dtls_retries)
            try:
                logger.debug("Probing %s inverter via DTLS at %s.", cls.__name__, host)
                await i.read_device_info()
                await i.read_runtime_data()
                logger.debug(
                    "Detected %s family inverter %s, S/N:%s via DTLS.",
                    cls.__name__, i.model_name, i.serial_number,
                )
                return i
            except InverterError as ex:
                failures.append(ex)

        raise InverterError(
            f"Detected DTLS dongle at {host} but could not identify inverter family.\n"
            f"Failures={str(failures)}"
        )

    # --- Plain UDP discovery (existing logic) ---
    if port == GOODWE_UDP_PORT:
        # Try the common AA55C07F0102000241 command first and detect inverter type from serial_number
        try:
            logger.debug("Probing inverter at %s:%s.", host, port)
            response = await DISCOVERY_COMMAND.execute(
                UdpInverterProtocol(host, port, timeout, retries)
            )
            response = response.response_data()
            model_name = response[5:15].decode("ascii").rstrip()
            serial_number = response[31:47].decode("ascii")

            i: Inverter | None = None
            for model_tag in ET_MODEL_TAGS:
                if model_tag in serial_number:
                    logger.debug(
                        "Detected ET/EH/BT/BH/GEH inverter %s, S/N:%s.",
                        model_name,
                        serial_number,
                    )
                    i = ET(host, port, 0, timeout, retries)
                    break
            if not i:
                for model_tag in ES_MODEL_TAGS:
                    if model_tag in serial_number:
                        logger.debug(
                            "Detected ES/EM/BP inverter %s, S/N:%s.",
                            model_name,
                            serial_number,
                        )
                        i = ES(host, port, 0, timeout, retries)
                        break
            if not i:
                for model_tag in DT_MODEL_TAGS:
                    if model_tag in serial_number:
                        logger.debug(
                            "Detected DT/MS/D-NS/XS/GEP inverter %s, S/N:%s.",
                            model_name,
                            serial_number,
                        )
                        i = DT(host, port, 0, timeout, retries)
                        break
            if i:
                await i.read_device_info()
                logger.debug(
                    "Connected to inverter %s, S/N:%s.", i.model_name, i.serial_number
                )
                return i

        except InverterError as ex:
            failures.append(ex)

    # Probe inverter specific protocols
    for inv in [ET, DT, ES]:
        i = inv(host, port, 0, timeout, retries)
        try:
            logger.debug("Probing %s inverter at %s.", inv.__name__, host)
            await i.read_device_info()
            await i.read_runtime_data()
            logger.debug(
                "Detected %s family inverter %s, S/N:%s.",
                inv.__name__,
                i.model_name,
                i.serial_number,
            )
            return i
        except InverterError as ex:
            failures.append(ex)
    raise InverterError(
        "Unable to connect to the inverter at "
        f"host={host}, or your inverter is not supported yet.\n"
        f"Failures={str(failures)}"
    )


async def search_inverters() -> bytes:
    """Scan the network for inverters.
    Answer the inverter discovery response string (which includes its IP address).

    Raise InverterError if unable to contact any inverter.
    """
    logger.debug("Searching inverters by broadcast to port 48899")
    command = ProtocolCommand(_DISCOVERY_48899_PAYLOAD.encode("utf-8"), lambda r: True)
    try:
        result = await command.execute(
            UdpInverterProtocol("255.255.255.255", 48899, 1, 0)
        )
        if result is not None:
            return result.response_data()
        raise InverterError("No response received to broadcast request.")
    except asyncio.CancelledError:
        raise InverterError(
            "No valid response received to broadcast request."
        ) from None
