import asyncio
import sys
import logging
from client.peer_client import SecurePeerClient

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)


async def input_loop(peer):
    loop = asyncio.get_running_loop()
    while True:
        try:
            message = await loop.run_in_executor(None, input)
            peer.send_message(message)
        except EOFError:
            break
        except Exception as e:
            logger.error(f"✗ Input error: {e}")


async def main(name, listen_port, peer_ip, peer_port, private_key_path, public_key_path, relay_ip=None, relay_port=None):
    relay_server = (relay_ip, relay_port) if relay_ip and relay_port else None
    peer = SecurePeerClient(name, listen_port, peer_ip, peer_port, private_key_path, public_key_path, relay_server)
    await peer.start()
    await input_loop(peer)


if __name__ == "__main__":
    if len(sys.argv) < 7:
        print("Usage: python main.py <name> <listen_port> <peer_ip> <peer_port> <private_key> <public_key> [relay_ip] [relay_port]")
        print("\nExample with relay (SIP-style - relay for signaling, direct for media):")
        print("  Alice: python main.py Alice 9001 UNKNOWN 9002 alice_privkey.pem alice_pubkey.pem 203.0.113.5 8000")
        print("  Bob:   python main.py Bob 9002 UNKNOWN 9001 bob_privkey.pem bob_pubkey.pem 203.0.113.5 8000")
        print("\nNote: Use 'UNKNOWN' for peer_ip when behind NAT - relay will exchange addresses")
        sys.exit(1)

    name = sys.argv[1]
    listen_port = int(sys.argv[2])
    peer_ip = sys.argv[3]
    peer_port = int(sys.argv[4])
    private_key_path = sys.argv[5]
    public_key_path = sys.argv[6]
    relay_ip = sys.argv[7] if len(sys.argv) > 7 else None
    relay_port = int(sys.argv[8]) if len(sys.argv) > 8 else None

    asyncio.run(main(name, listen_port, peer_ip, peer_port, private_key_path, public_key_path, relay_ip, relay_port))
