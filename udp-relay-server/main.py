import asyncio
import socket
from server.relay_server import RelayServer
from server.protocol import RelayProtocol
from utils.logger import logger


async def main():
    server = RelayServer()
    loop = asyncio.get_running_loop()
    
    # Check port availability
    logger.info("Checking port 8000...")
    try:
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        test_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        test_sock.bind(('0.0.0.0', 8000))
        local_addr = test_sock.getsockname()
        logger.info(f"Port 8000 available at {local_addr}")
        test_sock.close()
    except OSError as e:
        logger.error(f"Port 8000 unavailable: {e}")
        return
    
    logger.info("Starting relay server...")
    
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: RelayProtocol(server),
        local_addr=('0.0.0.0', 8000)
    )
    
    logger.info("Relay server ready")
    logger.info("Waiting for connections...")
    logger.info("")
    
    try:
        await asyncio.Event().wait()
    finally:
        if server.keepalive_task:
            server.keepalive_task.cancel()
        transport.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("\nRelay server stopped")
