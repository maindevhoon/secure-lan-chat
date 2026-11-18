"""Wire format shared by the TCP client and server."""

import hashlib
import json
import re
import struct
from time import monotonic

PORT = 7443
MAX_FILE = 8 * 1024 * 1024
MAX_HEADER = 384 * 1024
MAX_TEXT = 2000
IO_TIMEOUT = 20
PREFIX = struct.Struct("!II")
USERNAME = re.compile(r"[A-Za-z0-9_-]{1,24}")
FILE_ID = re.compile(r"[0-9a-f]{32}")


class ProtocolError(ValueError):
    pass


def read_exact(sock, size, deadline):
    buffer = bytearray(size)
    view = memoryview(buffer)
    while view:
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise TimeoutError("Frame read timed out")
        sock.settimeout(remaining)
        received = sock.recv_into(view)
        if not received:
            raise EOFError("Connection closed")
        view = view[received:]
    return bytes(buffer)


def receive(sock):
    deadline = monotonic() + IO_TIMEOUT
    header_size, data_size = PREFIX.unpack(read_exact(sock, PREFIX.size, deadline))
    if not 0 < header_size <= MAX_HEADER or data_size > MAX_FILE:
        raise ProtocolError("Frame exceeds size limits")
    try:
        header = json.loads(read_exact(sock, header_size, deadline))
    except (ValueError, RecursionError) as exc:
        raise ProtocolError("Invalid JSON header") from exc
    if not isinstance(header, dict):
        raise ProtocolError("Expected a JSON object")
    return header, read_exact(sock, data_size, deadline)


def send(sock, header, data=b""):
    encoded = json.dumps(header, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )
    if len(encoded) > MAX_HEADER or len(data) > MAX_FILE:
        raise ProtocolError("Frame exceeds size limits")
    sock.settimeout(IO_TIMEOUT)
    sock.sendall(PREFIX.pack(len(encoded), len(data)) + encoded)
    if data:
        sock.sendall(data)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def safe_filename(name):
    return (
        isinstance(name, str)
        and 1 <= len(name) <= 120
        and re.fullmatch(r"[A-Za-z0-9_. -]+", name) is not None
        and name[0].isalnum()
        and not name.endswith((".", " "))
        and name.split(".", 1)[0].upper().rstrip()
        not in {
            "CON",
            "PRN",
            "AUX",
            "NUL",
            *(f"COM{i}" for i in range(1, 10)),
            *(f"LPT{i}" for i in range(1, 10)),
        }
    )
