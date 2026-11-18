import argparse
import hmac
import logging
import os
import socket
import socketserver
import sqlite3
import ssl
import threading
from collections import deque
from pathlib import Path

from . import protocol
from .storage import Store

LOG = logging.getLogger("lanchat")
MAX_CONNECTIONS = 24
MAX_EVENTS = 32


class Mailbox:
    def __init__(self):
        self.events = deque(maxlen=MAX_EVENTS)
        self.dropped = 0

    def append(self, event):
        if len(self.events) == MAX_EVENTS:
            self.dropped += 1
        self.events.append(event)

    def drain(self):
        result = {"events": list(self.events), "missed_events": self.dropped}
        self.events.clear()
        self.dropped = 0
        return result


class ChatServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, store, context, room_key):
        super().__init__(address, ChatHandler)
        self.store = store
        self.context = context
        self.room_key = room_key.encode()
        self.room_lock = threading.Lock()
        self.users = {}
        self.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self.hostname = socket.gethostname()

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def broadcast(self, event, exclude):
        with self.room_lock:
            self._broadcast(event, exclude)

    def _broadcast(self, event, exclude):
        for name, mailbox in self.users.items():
            if name != exclude:
                mailbox.append(event)

    def join(self, name, key):
        if not isinstance(name, str) or not protocol.USERNAME.fullmatch(name):
            raise ValueError(
                "Use 1–24 letters, numbers, hyphens or underscores for your name"
            )
        if self.room_key and (
            not isinstance(key, str)
            or not hmac.compare_digest(
                self.room_key, key.encode("utf-8", errors="replace")
            )
        ):
            raise ValueError("Incorrect room key")
        with self.room_lock:
            if any(user.casefold() == name.casefold() for user in self.users):
                raise ValueError("That username is already connected")
            mailbox = self.users[name] = Mailbox()
            self._broadcast({"kind": "join", "user": name}, name)
            return mailbox

    def leave(self, name):
        with self.room_lock:
            del self.users[name]
            self._broadcast({"kind": "leave", "user": name}, name)


class ChatHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.name = None
        try:
            self.request.settimeout(protocol.IO_TIMEOUT)
            self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock = self.request
            if self.server.context:
                sock = self.server.context.wrap_socket(sock, server_side=True)
            with sock:
                self.serve(sock)
        except (EOFError, OSError, protocol.ProtocolError):
            pass
        finally:
            if self.name is not None:
                self.server.leave(self.name)

    def serve(self, sock):
        header, data = protocol.receive(sock)
        try:
            if header.get("op") != "hello" or data:
                raise ValueError("The first frame must be hello")
            name = header.get("name")
            mailbox = self.server.join(name, header.get("key"))
        except ValueError as exc:
            protocol.send(sock, {"ok": False, "error": str(exc)})
            return
        self.name = name
        protocol.send(
            sock,
            {
                "ok": True,
                "server_host": self.server.hostname,
                "observed_ip": self.client_address[0],
            },
        )
        while True:
            header, data = protocol.receive(sock)
            op = header.get("op")
            try:
                response, payload = self.dispatch(op, header, data)
                response["ok"] = True
            except ValueError as exc:
                response, payload = {"ok": False, "error": str(exc)}, b""
            except sqlite3.Error:
                LOG.exception("File storage operation failed")
                response, payload = (
                    {"ok": False, "error": "File storage operation failed"},
                    b"",
                )
            if op == "quit":
                self.server.leave(self.name)
                self.name = None
            with self.server.room_lock:
                response.update(mailbox.drain())
            protocol.send(sock, response, payload)
            if op == "quit":
                return

    def dispatch(self, op, header, data):
        if data and op != "upload":
            raise ValueError("This operation does not accept file data")
        if op in ("poll", "ping", "quit"):
            return {}, b""
        if op == "users":
            with self.server.room_lock:
                return {"users": sorted(self.server.users, key=str.casefold)}, b""
        if op == "chat":
            message = header.get("message")
            if (
                not isinstance(message, str)
                or not message.strip()
                or len(message) > protocol.MAX_TEXT
                or not message.isprintable()
            ):
                raise ValueError("Messages must contain 1–2000 printable characters")
            self.server.broadcast(
                {"kind": "chat", "user": self.name, "message": message}, self.name
            )
            return {}, b""
        if op == "upload":
            name = header.get("name")
            if not protocol.safe_filename(name):
                raise ValueError(
                    "Use a short filename with letters, numbers, spaces, dots, _ or -"
                )
            digest = protocol.sha256(data)
            if header.get("digest") != digest:
                raise ValueError("File digest mismatch")
            entry = self.server.store.put(name, self.name, digest, data)
            self.server.broadcast({"kind": "file", "file": entry}, self.name)
            return {"file": entry}, b""
        if op == "files":
            return {"files": self.server.store.list()}, b""
        if op == "download":
            file_id = header.get("id")
            if not isinstance(file_id, str) or not protocol.FILE_ID.fullmatch(file_id):
                raise ValueError("Use a file ID shown by /files")
            entry, payload = self.server.store.get(file_id)
            return {"file": entry}, payload
        raise ValueError("Unknown operation")


def main():
    parser = argparse.ArgumentParser(description="Secure LAN chat TCP server")
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=protocol.PORT)
    parser.add_argument("--cert", type=Path, default=Path("/keys/server.crt"))
    parser.add_argument("--key", type=Path, default=Path("/keys/server.key"))
    parser.add_argument("--database", type=Path, default=Path("/data/chat.sqlite3"))
    parser.add_argument("--plaintext-lab", action="store_true")
    args = parser.parse_args()
    room_key = os.environ.get("CHAT_ROOM_KEY", "")
    context = None
    if args.plaintext_lab:
        if args.bind != "127.0.0.1" or room_key:
            parser.error(
                "The plaintext lab requires IPv4 loopback and an empty room key"
            )
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(args.cert, args.key)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args.database.parent.mkdir(parents=True, exist_ok=True)
    with ChatServer(
        (args.bind, args.port), Store(args.database), context, room_key
    ) as server:
        LOG.info(
            "%s listening on %s:%s",
            "TLS" if context else "Plaintext lab",
            *server.server_address,
        )
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
