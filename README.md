# UDP Relay Server

The UDP Relay Server is a lightweight Python-based component of the Decentralized Chat application. It enables secure peer-to-peer chat by facilitating initial connections, with a strong preference for direct IP-based communication between peers.

## Key Features

- **Direct Peer-to-Peer Priority**: Peers chat securely directly via IP addresses once connected; relay only assists connection establishment.
- **Fallback Relay**: If direct connection fails (e.g., due to NAT), relay server passes encrypted messages without logging or storing them.
- **Privacy-Focused**: No chat message logging, storage, or decryption by the relay server.
- **Async UDP Handling**: Efficient session tracking and message routing using asyncio.
- **NAT Traversal**: Helps peers behind NAT communicate by relaying messages
- **Peer Discovery**: Automatic peer registration and discovery
- **Keepalive Management**: Maintains NAT bindings with periodic keepalives
- **Stale Peer Cleanup**: Automatically removes inactive peers
- **Simple Protocol**: JSON-based message format

## Requirements

- Python 3.8+ (standard library only: asyncio, struct).

## Installation

1. Clone: `git clone https://github.com/BitDataCoin/decentralized-chat.git`
2. Navigate: `cd decentralized-chat/udp-relay-server`
3. Run: `python main.py --host 0.0.0.0 --port 8000`

## Windows Firewall Setup
On Windows, Alice and Bob open UDP ports:

**Allow ports:**

netsh advfirewall firewall add rule name="Alice" dir=in action=allow protocol=UDP localport=9001
netsh advfirewall firewall add rule name="Bob" dir=in action=allow protocol=UDP localport=9002


**Check status:**
netsh advfirewall firewall show rule name="Alice"
netsh advfirewall firewall show rule name="Bob"


**Disable (if needed):**
netsh advfirewall firewall set rule name="Alice" new enable=no
netsh advfirewall firewall set rule name="Bob" new enable=no

## Peer Connection Example
Alice and Bob connect directly after obtaining each other's IP:

**Alice's terminal:**
python peer_secure_mobile.py Alice 9001 <BOB_IP> 9002 alice_privkey.pem alice_pubkey.pem <RELAY_IP> 8000


**Bob's terminal:**
python peer_secure_mobile.py Bob 9002 <ALICE_IP> 9001 bob_privkey.pem bob_pubkey.pem <RELAY_IP> 8000

Replace `<BOB_IP>`, `<ALICE_IP>`, and `<RELAY_IP>` with actual addresses. Relay enables direct secure chat or falls back transparently.

## Architecture

- `main.py`: Server entry point.
- `server/relay_server.py`: Core async relay logic.
- `server/protocol.py`: Packet formats.
- `server/__init__.py`: Package init.

## Contributing

Fork, enhance peer connection logic, test direct/relay paths, submit PR.


MIT License.