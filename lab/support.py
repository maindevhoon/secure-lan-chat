import os
import ssl
import subprocess
import threading
from contextlib import contextmanager
from pathlib import Path

from lanchat.server import ChatServer
from lanchat.storage import Store

LAB = Path(__file__).resolve().parent


def certificate(directory):
    keys, trust = directory / "keys", directory / "trust"
    subprocess.run(
        ["sh", str(LAB / "certs.sh"), str(keys), str(trust)],
        env={**os.environ, "CHAT_LAN_IP": ""},
        check=True,
        capture_output=True,
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(keys / "server.crt", keys / "server.key")
    return context, trust / "server.crt"


@contextmanager
def room(database, context, room_key="", port=0):
    store = Store(database)
    try:
        with ChatServer(("127.0.0.1", port), store, context, room_key) as server:
            worker = threading.Thread(
                target=server.serve_forever, kwargs={"poll_interval": 0.05}
            )
            worker.start()
            try:
                yield server.server_address[1]
            finally:
                server.shutdown()
                worker.join()
                # The callers close all clients before leaving this context.
    finally:
        store.db.close()
