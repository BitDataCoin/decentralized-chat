import asyncio
import socket
from utils.logger import logger


class RelayProtocol(asyncio.DatagramProtocol):
    def __init__(self, server):
        self.server = server
    
    def connection_made(self, transport):
        self.server.transport = transport
        sock = transport.get_extra_info('socket')
        sockname = sock.getsockname()
        
        logger.info("=" * 70)
        logger.info("RELAY SERVER STARTED")
        logger.info(f"Bound to: {sockname}")
        logger.info(f"Listening on: 0.0.0.0:8000")
        
        # Get local IPs
        hostname = socket.gethostname()
        try:
            local_ips = socket.gethostbyname_ex(hostname)[2]
            logger.info(f"Local IPs: {local_ips}")
        except:
            pass
        
        # Socket options
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, 'SO_REUSEPORT'):
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except:
                pass
        
        logger.info("=" * 70)
        logger.info("")
        
        # Start keepalive task
        self.server.keepalive_task = asyncio.create_task(
            self.server.send_periodic_keepalives()
        )
    
    def datagram_received(self, data, addr):
        self.server.datagram_received(data, addr)
    
    def error_received(self, exc):
        logger.error(f"Protocol error: {exc}")
