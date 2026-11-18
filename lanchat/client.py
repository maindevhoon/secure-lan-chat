import argparse
import getpass
import socket
import ssl
import sys
import threading
from pathlib import Path
from time import monotonic

from . import protocol

HELP = """
Type a message and press Enter to send it to the room.
/users            List connected users
/send PATH        Upload a file from your /client mount (8 MiB max)
/files            List shared files and their IDs
/get ID           Save a verified copy to your download directory
/ping             Measure application round-trip time
/info             Show hostnames, addresses and TLS details
/help             Show commands
/quit             Leave the room
""".strip()


class Client:
    def __init__(self, host, port, name, cert, key="", plaintext=False):
        if plaintext and (host != "127.0.0.1" or key):
            raise ValueError(
                "The plaintext lab requires IPv4 loopback and an empty room key"
            )
        context = None
        if not plaintext:
            context = ssl.create_default_context(cafile=str(cert))
            context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.sock = socket.create_connection((host, port), timeout=5)
        try:
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if context:
                self.sock = context.wrap_socket(self.sock, server_hostname=host)
            self.session, _ = self.request("hello", name=name, key=key)
            self.session.update(
                {
                    "local_host": socket.gethostname(),
                    "local_address": self.sock.getsockname(),
                    "server_address": self.sock.getpeername(),
                    "transport": f"{self.sock.version()} / {self.sock.cipher()[0]}"
                    if context
                    else "Plain TCP",
                }
            )
        except BaseException:
            self.sock.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.sock.close()

    def request(self, op, data=b"", **fields):
        protocol.send(self.sock, {"op": op, **fields}, data)
        reply, payload = protocol.receive(self.sock)
        if not reply.get("ok") and op == "hello":
            raise ValueError(reply.get("error", "Connection rejected"))
        return reply, payload


def show_file(entry):
    print(
        f"{entry['id']}  {entry['name']}  ({entry['size']:,} bytes, {entry['owner']})"
    )


def show_events(reply):
    for event in reply.get("events", []):
        kind = event["kind"]
        if kind == "chat":
            print(f"{event['user']}> {event['message']}", flush=True)
        elif kind == "file":
            print(f"* New file from {event['file']['owner']}", flush=True)
            show_file(event["file"])
        else:
            action = "joined" if kind == "join" else "left"
            print(f"* {event['user']} {action}", flush=True)
    if reply.get("missed_events"):
        print(f"* {reply['missed_events']} room events were skipped", flush=True)


def transfer_result(verb, size, elapsed):
    rate = size / max(elapsed, 1e-9) / 1024
    print(f"{verb} {size:,} bytes in {elapsed:.3f} s ({rate:,.1f} KiB/s)")


def save_download(directory, entry, payload):
    name = entry["name"]
    if not protocol.safe_filename(name):
        raise ValueError("Server supplied an invalid filename")
    if len(payload) != entry["size"] or protocol.sha256(payload) != entry["digest"]:
        raise ValueError("Download failed SHA-256 verification")
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / name
    with destination.open("xb") as file:
        try:
            file.write(payload)
            file.flush()
        except OSError:
            file.close()
            destination.unlink(missing_ok=True)
            raise
    return destination


def handle_line(line, call, session, directory, username):
    if not line.startswith("/"):
        call("chat", message=line)
        print(f"{username}> {line}")
        return
    command, _, argument = line.partition(" ")
    argument = argument.strip()
    if command == "/users":
        reply, _, _ = call("users")
        print(", ".join(reply["users"]))
    elif command == "/ping":
        _, _, elapsed = call("ping")
        print(f"Application RTT: {elapsed * 1000:.2f} ms")
    elif command == "/info":
        print(f"Client: {session['local_host']} {session['local_address']}")
        print(f"Server: {session['server_host']} {session['server_address']}")
        print(f"Client IP seen by server: {session['observed_ip']}")
        print(f"Transport: {session['transport']}")
    elif command == "/send":
        if argument.startswith(('"', "'")) and argument.endswith(argument[0]):
            argument = argument[1:-1]
        path = Path(argument).expanduser()
        if not protocol.safe_filename(path.name) or not path.is_file():
            raise ValueError(
                "Use /send PATH with a readable file and a supported filename"
            )
        with path.open("rb") as file:
            data = file.read(protocol.MAX_FILE + 1)
        if len(data) > protocol.MAX_FILE:
            raise ValueError("Files must be 8 MiB or smaller")
        reply, _, elapsed = call(
            "upload", data, name=path.name, digest=protocol.sha256(data)
        )
        transfer_result("Uploaded", len(data), elapsed)
        show_file(reply["file"])
    elif command == "/files":
        reply, _, _ = call("files")
        for entry in reply["files"]:
            show_file(entry)
        if not reply["files"]:
            print("No files have been shared yet.")
    elif command == "/get":
        reply, data, elapsed = call("download", id=argument)
        path = save_download(directory, reply["file"], data)
        transfer_result("Downloaded", len(data), elapsed)
        print(f"SHA-256 verified. Saved to {path}")
    elif command == "/help":
        print(HELP)
    else:
        raise ValueError("Unknown command. Type /help")


def interactive(client, name, directory):
    stopped = threading.Event()
    socket_lock = threading.Lock()

    def call(op, data=b"", **fields):
        # A request and its reply must finish before the next thread uses the socket.
        with socket_lock:
            if op == "poll" and stopped.is_set():
                return None
            started = monotonic()
            try:
                reply, payload = client.request(op, data, **fields)
            except (EOFError, OSError, protocol.ProtocolError, KeyboardInterrupt):
                stopped.set()
                raise
            elapsed = monotonic() - started
            show_events(reply)
        if not reply["ok"]:
            raise ValueError(reply["error"])
        return reply, payload, elapsed

    def poll():
        try:
            while not stopped.wait(0.35):
                call("poll")
        except (EOFError, OSError, protocol.ProtocolError) as exc:
            print(f"Connection lost: {exc}", file=sys.stderr, flush=True)

    worker = threading.Thread(target=poll)
    worker.start()
    print(
        f"Connected as {name} using {client.session['transport']}. Type /help for commands."
    )
    try:
        while not stopped.is_set():
            line = input().strip()
            if line == "/quit" or stopped.is_set():
                break
            if line:
                try:
                    handle_line(line, call, client.session, directory, name)
                except (OSError, ValueError) as exc:
                    print(f"Error: {exc}", file=sys.stderr)
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        stopped.set()
        worker.join()


def main():
    parser = argparse.ArgumentParser(description="Secure LAN chat terminal client")
    parser.add_argument("name")
    parser.add_argument("--host", default="server")
    parser.add_argument("--port", default=protocol.PORT, type=int)
    parser.add_argument("--cert", default=Path("/trust/server.crt"), type=Path)
    parser.add_argument("--downloads", default=Path("/client/downloads"), type=Path)
    parser.add_argument("--ask-key", action="store_true")
    args = parser.parse_args()
    if not protocol.USERNAME.fullmatch(args.name):
        parser.error("Name must contain 1–24 letters, numbers, hyphens or underscores")
    key = getpass.getpass("Room key: ") if args.ask_key else ""
    try:
        with Client(args.host, args.port, args.name, args.cert, key) as client:
            interactive(client, args.name, args.downloads)
    except (OSError, EOFError, ValueError) as exc:
        parser.exit(1, f"Connection failed: {exc}\n")


if __name__ == "__main__":
    main()
