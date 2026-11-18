import socket
import ssl
import tempfile
import unittest
from pathlib import Path

from lab.support import certificate, room
from lanchat import protocol
from lanchat.client import Client, save_download


class WireTests(unittest.TestCase):
    def test_framing_keeps_binary_data_and_message_boundaries(self):
        sender, receiver = socket.socketpair()
        with sender, receiver:
            protocol.send(sender, {"message": "héllo 👋"}, b"\x00\xff")
            protocol.send(sender, {"op": "ping"})
            self.assertEqual(
                protocol.receive(receiver), ({"message": "héllo 👋"}, b"\x00\xff")
            )
            self.assertEqual(protocol.receive(receiver), ({"op": "ping"}, b""))

    def test_rejects_oversized_frames_before_reading_body(self):
        sender, receiver = socket.socketpair()
        with sender, receiver:
            sender.sendall(protocol.PREFIX.pack(2, protocol.MAX_FILE + 1))
            with self.assertRaises(protocol.ProtocolError):
                protocol.receive(receiver)


class ChatTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temp.cleanup)
        cls.directory = Path(temp.name)
        cls.context, cls.cert = certificate(cls.directory)

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db = Path(temp.name) / "chat.sqlite3"

    def connect(self, port, name, key="", host="127.0.0.1", cert=None):
        return Client(host, port, name, cert or self.cert, key=key)

    def test_room_chat_presence_rtt_and_duplicate_user(self):
        with (
            room(self.db, self.context) as port,
            self.connect(port, "Alice") as alice,
            self.connect(port, "Bob") as bob,
        ):
            self.assertIn(
                alice.session["transport"].split("/")[0].strip(), {"TLSv1.2", "TLSv1.3"}
            )
            self.assertEqual(alice.session["observed_ip"], "127.0.0.1")
            with self.assertRaisesRegex(ValueError, "already connected"):
                self.connect(port, "alice")
            reply, _ = alice.request("users")
            self.assertEqual(reply["users"], ["Alice", "Bob"])
            self.assertIn({"kind": "join", "user": "Bob"}, reply["events"])
            alice.request("chat", message="Hello 👋")
            reply, _ = bob.request("ping")
            self.assertTrue(reply["ok"])
            self.assertIn(
                {"kind": "chat", "user": "Alice", "message": "Hello 👋"},
                reply["events"],
            )
            bob.request("quit")
            reply, _ = alice.request("users")
            self.assertEqual(reply["users"], ["Alice"])

    def test_rejects_wrong_room_key_and_untrusted_certificate(self):
        with room(self.db, self.context, "classroom-key") as port:
            with self.assertRaisesRegex(ValueError, "Incorrect room key"):
                self.connect(port, "Alice", "incorrect-key")
            with tempfile.TemporaryDirectory() as temp:
                _, unrelated = certificate(Path(temp))
                with self.assertRaises(ssl.SSLCertVerificationError):
                    self.connect(port, "Alice", "classroom-key", cert=unrelated)
            with self.connect(
                port, "Alice", "classroom-key", host="localhost"
            ) as alice:
                self.assertTrue(alice.session["ok"])

    def test_file_digest_filename_notification_download_and_persistence(self):
        data = bytes(range(256)) * 101
        digest = protocol.sha256(data)
        with (
            room(self.db, self.context) as port,
            self.connect(port, "Alice") as alice,
            self.connect(port, "Bob") as bob,
        ):
            reply, _ = alice.request("upload", data, name="../x.bin", digest=digest)
            self.assertFalse(reply["ok"])
            reply, _ = alice.request("upload", data, name="x.bin", digest="bad")
            self.assertFalse(reply["ok"])
            reply, _ = alice.request(
                "upload", data, name="report copy.bin", digest=digest
            )
            entry = reply["file"]
            reply, _ = bob.request("files")
            self.assertEqual(reply["files"], [entry])
            self.assertIn({"kind": "file", "file": entry}, reply["events"])
        with room(self.db, self.context) as port, self.connect(port, "Bob") as bob:
            reply, downloaded = bob.request("download", id=entry["id"])
            self.assertEqual(reply["file"], entry)
            self.assertEqual(downloaded, data)
            folder = self.db.parent / "downloads"
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                save_download(folder, entry, b"\x00" * len(data))
            path = save_download(folder, entry, downloaded)
            self.assertEqual(path.read_bytes(), data)
            with self.assertRaises(FileExistsError):
                save_download(folder, entry, downloaded)

    def test_unicode_chat_burst_fits_frame_and_counts_missed_events(self):
        with (
            room(self.db, self.context) as port,
            self.connect(port, "Alice") as alice,
            self.connect(port, "Bob") as bob,
        ):
            for _ in range(33):
                reply, _ = alice.request("chat", message="🙂" * protocol.MAX_TEXT)
                self.assertTrue(reply["ok"])
            reply, _ = bob.request("files")
            self.assertEqual(reply["missed_events"], 1)
            self.assertEqual(len(reply["events"]), 32)
