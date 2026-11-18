"""Capture traffic created by two synthetic clients inside the lab container."""

import argparse
import selectors
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from time import monotonic

from lanchat.client import Client
from lanchat.protocol import PORT, sha256

from .support import certificate, room

MARKER = "LANCHAT_CLASSROOM_MESSAGE"
FILE_MARKER = b"LANCHAT_CLASSROOM_FILE"


@contextmanager
def tcpdump(output):
    with (
        subprocess.Popen(
            [
                "tcpdump",
                "-Z",
                "root",
                "-i",
                "lo",
                "--immediate-mode",
                "-n",
                "-U",
                "-s",
                "0",
                "-w",
                str(output),
                "tcp",
                "port",
                str(PORT),
            ],
            stderr=subprocess.PIPE,
        ) as process,
        selectors.DefaultSelector() as selector,
    ):
        selector.register(process.stderr, selectors.EVENT_READ)
        try:
            if not selector.select(5):
                raise RuntimeError("Timed out starting tcpdump")
            line = process.stderr.readline()
            if b"listening on" not in line:
                raise RuntimeError(line.decode(errors="replace").strip())
            yield
        finally:
            if process.poll() is None:
                process.terminate()
            _, diagnostics = process.communicate(timeout=10)
            if process.returncode:
                raise RuntimeError(diagnostics.decode(errors="replace").strip())


def exercise(cert, plaintext):
    with (
        Client("127.0.0.1", PORT, "Alice", cert, plaintext=plaintext) as alice,
        Client("127.0.0.1", PORT, "Bob", cert, plaintext=plaintext) as bob,
    ):
        alice.request("chat", message=MARKER)
        received, _ = bob.request("poll")
        if not any(event.get("message") == MARKER for event in received["events"]):
            raise RuntimeError("Chat relay failed")
        started = monotonic()
        payload = FILE_MARKER + b"\x00\x01" * 2048
        uploaded, _ = alice.request(
            "upload", payload, name="classroom.bin", digest=sha256(payload)
        )
        upload_ms = (monotonic() - started) * 1000
        file_id = uploaded["file"]["id"]
        started = monotonic()
        _, downloaded = bob.request("download", id=file_id)
        download_ms = (monotonic() - started) * 1000
        if downloaded != payload:
            raise RuntimeError("File transfer failed")
        alice.request("quit")
        bob.request("quit")
        return f"{alice.session['transport']}, {len(payload)} bytes, upload {upload_ms:.2f} ms, download {download_ms:.2f} ms"


def frame_count(path, display_filter):
    frames = subprocess.check_output(
        [
            "tshark",
            "-r",
            str(path),
            "-d",
            f"tcp.port=={PORT},tls",
            "-Y",
            display_filter,
            "-T",
            "fields",
            "-e",
            "frame.number",
        ],
        stderr=subprocess.PIPE,
        text=True,
    )
    return len(frames.splitlines())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("/results"))
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    report = []
    with tempfile.TemporaryDirectory() as temp:
        directory = Path(temp)
        context, cert = certificate(directory)
        for mode in ("plaintext", "tls"):
            plaintext = mode == "plaintext"
            output = args.out / f"{mode}.pcap"
            with (
                room(
                    directory / f"{mode}.db", None if plaintext else context, port=PORT
                ),
                tcpdump(output),
            ):
                transport = exercise(cert, plaintext)
            chat = frame_count(output, f'tcp contains "{MARKER}"')
            files = frame_count(output, f'tcp contains "{FILE_MARKER.decode()}"')
            tls = frame_count(
                output, "tls.record.content_type == 23 || tls.record.opaque_type == 23"
            )
            if plaintext and (not chat or not files):
                raise RuntimeError("Plaintext markers are missing")
            if not plaintext and (chat or files or not tls):
                raise RuntimeError(
                    f"Unexpected TLS capture counts: {chat=} {files=} {tls=}"
                )
            report.append(
                f"{mode}: {transport}\n"
                f"  frames containing chat marker: {chat}\n"
                f"  frames containing file marker: {files}\n"
                f"  Frames with encrypted TLS records: {tls}"
            )
    summary = "\n".join(report) + "\n"
    (args.out / "capture-summary.txt").write_text(summary)
    print(summary, end="")


if __name__ == "__main__":
    main()
