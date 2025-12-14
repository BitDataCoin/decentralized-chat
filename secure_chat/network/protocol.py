import asyncio
import logging

logger = logging.getLogger(__name__)


class SecurePeerProtocol(asyncio.DatagramProtocol):
    def __init__(self, peer_client):
        self.peer_client = peer_client

    def datagram_received(self, data, addr):
        self.peer_client.receive_message(data, addr)

    def error_received(self, exc):
        if exc:
            logger.error(f"✗ Protocol error: {exc}")

    def connection_lost(self, exc):
        if exc:
            logger.info(f"Connection lost: {exc}")
