# Secure LAN Chat and File Sharing

Two people open a terminal and connect to the same Python server. They can chat, share files, and measure how long a request takes. Docker Compose starts the server and clients.

## Five-minute demo

Open a terminal in this folder with Docker running.

```sh
mkdir -p runtime/client
echo "Hello from Alice" > runtime/client/demo.txt
docker compose up --build -d --wait
docker compose run --rm --build client Alice
```

In a second terminal in the same folder, run `docker compose run --rm client Bob`.

1. Type any message as Alice. It appears in Bob's terminal.
2. Type `/send /client/demo.txt` as Alice. Bob sees the file name and ID.
3. Copy that ID and type `/get ID` as Bob. The verified file appears in `runtime/client/downloads/`.
4. Try `/ping` to measure round-trip time and `/info` to see addresses and the TLS connection.

Type `/help` for the full command list or `/quit` to leave. When you're done, run `docker compose down`. Shared files stay in the server's Docker volume.

On Windows PowerShell, replace `mkdir -p runtime/client` with `New-Item -ItemType Directory -Force runtime/client`. On Linux, set `CHAT_UID` and `CHAT_GID` in `.env` if your user or group ID differs from 1000. Use the values from `id -u` and `id -g`.

## How to explain it

1. **TCP** carries messages and files in order. Each request starts with lengths so the receiver knows where the message and file bytes end.
2. **TLS** encrypts traffic. The client uses a copy of the server's public certificate to check that it connected to the right server.
3. **Chat** goes through the server. The server queues a message for each recipient, and each client checks for new messages about three times a second.
4. **Files** go to the server's SQLite database. The server checks the file's SHA-256 on upload, and the client checks it again before saving a download.
5. **Measurements** come from timing a request and its reply. `/ping` shows application round-trip time. Upload and download show elapsed time and KiB/s.

| File | What it does |
| --- | --- |
| `lanchat/server.py` | Accepts clients, relays messages and handles file requests |
| `lanchat/client.py` | Reads terminal commands and checks for new messages |
| `lanchat/protocol.py` | Defines how to send, receive and validate data |
| `lanchat/storage.py` | Saves and retrieves shared files in SQLite |
| `compose.yaml` | Starts the certificate setup, server, clients and lab |
| `lab/` | Runs the packet capture and network simulation |

Anyone admitted to the room can see its shared files. The server keeps no chat history. Files can be up to 8 MiB each. TLS protects traffic in transit, and the server stores files in readable form.

## Wireshark demo

```sh
docker compose build lab
docker compose run --rm lab python -m lab.capture
```

Open `runtime/results/plaintext.pcap` and `runtime/results/tls.pcap` in Wireshark. Apply `tcp contains "LANCHAT_CLASSROOM_MESSAGE"` to each capture. The text matches in plaintext and disappears under TLS. Clear the filter to see the addresses, ports and packet sizes. Use **Decode As → TLS** for TCP port 7443 to inspect the TLS handshake and records. [Wireshark guide](https://www.wireshark.org/docs/wsug_html_chunked/)

Both captures use synthetic data inside an isolated Docker container. The chat service uses TLS for normal connections. Ready-made captures are in `sample-results/`.

## NS-2 demo

```sh
docker compose run --rm lab python -m lab.simulate
```

The experiment sends TCP traffic from a sender through a router to a receiver. It changes one link setting at a time. The bundled run measured these results over ten seconds. [NS-2 manual](https://www.isi.edu/websites/nsnam/ns/doc-stable/ns_doc.pdf)

| Case | Link delay | Packet loss | Throughput | Retransmissions |
| --- | ---: | ---: | ---: | ---: |
| Baseline | 5 ms | 0% | 1,992.67 kbit/s | 0 |
| Higher delay | 75 ms | 0% | 1,845.41 kbit/s | 0 |
| Packet loss | 5 ms | 3% | 1,168.99 kbit/s | 59 |

Higher delay lowered throughput in this run. Packet loss lowered it further and forced TCP to resend packets. The CSV and raw traces are written to `runtime/results/`.

## Run across two computers

1. On the server computer, find its IPv4 address on the shared Wi-Fi or Ethernet network. Copy `.env.example` to `.env` and set both `CHAT_BIND` and `CHAT_LAN_IP` to that address.
2. Run `docker compose up --build -d --wait --force-recreate`. Allow incoming TCP port 7443 through the server computer's LAN firewall.
3. Put a copy of this project on the second computer. Create `runtime/client/` and `runtime/trust/`. Copy the server's public `runtime/trust/server.crt` to the same path on the second computer through a trusted channel.
4. Start Bob on the second computer. Replace the example IP with the server's real address.

```sh
docker compose run --rm --build client Bob --host 192.168.1.20
```

To require a shared room key, set `CHAT_ROOM_KEY` in the server's `.env` before starting it and add `--ask-key` when connecting. If the server IP or certificate changes, share the updated public certificate. To use a different port, set `CHAT_PORT` on the server and pass `--port` to clients.

## Run tests

```sh
docker compose build lab
docker compose run --rm lab
```

The tests cover TLS verification, chat and presence, file upload and download, and file persistence.
