import asyncio
import json
import time
from utils.logger import logger


class RelayServer:
    def __init__(self):
        self.peers = {}  # peer_name -> {"addr": (ip, port), "last_seen": timestamp}
        self.transport = None
        self.packet_count = 0
        self.keepalive_task = None
    
    def datagram_received(self, data, addr):
        self.packet_count += 1
        logger.info("=" * 70)
        logger.info(f"PACKET #{self.packet_count} - Received {len(data)} bytes from {addr}")
        logger.info(f"Source: {addr[0]}:{addr[1]}")
        
        try:
            # Decode and log
            try:
                decoded = data.decode('utf-8')
                logger.debug(f"Decoded: {decoded[:500]}")
            except Exception as e:
                logger.debug(f"Binary data: {data[:100]}")
            
            packet = json.loads(data.decode())
            msg_type = packet.get("type")
            logger.info(f"Type: {msg_type}")
            
            if msg_type == "register":
                peer_name = packet.get("name")
                logger.info(f"REGISTER from: {peer_name}")
                
                # Store peer with timestamp
                self.peers[peer_name] = {
                    "addr": addr,
                    "last_seen": time.time()
                }
                
                logger.info(f"SUCCESS: Registered {peer_name} at {addr}")
                logger.info(f"Active peers: {list(self.peers.keys())}")
                
                # IMMEDIATE response - critical for NAT traversal
                response = json.dumps({
                    "type": "register_ack",
                    "status": "success",
                    "your_address": f"{addr[0]}:{addr[1]}",
                    "server_time": time.time(),
                    "peer_name": peer_name
                }).encode()
                
                self.transport.sendto(response, addr)
                logger.info(f"Sent register_ack to {peer_name} at {addr}")
                
                # Send peer list
                peer_list = list(self.peers.keys())
                peer_info = json.dumps({
                    "type": "peer_list",
                    "peers": peer_list,
                    "count": len(peer_list)
                }).encode()
                self.transport.sendto(peer_info, addr)
                logger.info(f"Sent peer_list to {peer_name}: {peer_list}")
                
                # Notify other peers
                for other_name, other_data in self.peers.items():
                    if other_name != peer_name:
                        other_addr = other_data["addr"]
                        notification = json.dumps({
                            "type": "peer_joined",
                            "peer_name": peer_name,
                            "peers": peer_list
                        }).encode()
                        self.transport.sendto(notification, other_addr)
                        logger.info(f"Notified {other_name} about {peer_name}")
                
            elif msg_type == "relay":
                target_name = packet.get("target")
                payload = packet.get("payload")
                source_name = packet.get("source", "unknown")
                
                logger.info(f"RELAY: {source_name} -> {target_name}")
                
                if target_name in self.peers:
                    target_addr = self.peers[target_name]["addr"]
                    
                    # Wrap the payload with relay metadata so receiver knows it came via relay
                    relay_wrapper = json.dumps({
                        "type": "relayed_packet",
                        "from_peer": source_name,
                        "via_relay": True,
                        "payload": payload
                    }).encode('utf-8')
                    
                    self.transport.sendto(relay_wrapper, target_addr)
                    logger.info(f"Relayed {len(relay_wrapper)} bytes to {target_name} at {target_addr}")
                    
                    # Update last_seen for source
                    if source_name in self.peers:
                        self.peers[source_name]["last_seen"] = time.time()
                else:
                    logger.warning(f"Target {target_name} not found. Available: {list(self.peers.keys())}")
                    
            elif msg_type == "keepalive":
                peer_name = packet.get("name")
                if peer_name:
                    old_data = self.peers.get(peer_name, {})
                    old_addr = old_data.get("addr")
                    
                    self.peers[peer_name] = {
                        "addr": addr,
                        "last_seen": time.time()
                    }
                    
                    if old_addr != addr:
                        logger.info(f"Address updated for {peer_name}: {old_addr} -> {addr}")
                    else:
                        logger.debug(f"Keepalive from {peer_name}")
                    
                    # Send keepalive response
                    response = json.dumps({
                        "type": "keepalive_ack",
                        "peer_name": peer_name,
                        "server_time": time.time()
                    }).encode()
                    self.transport.sendto(response, addr)
                    
            elif msg_type == "ping":
                # Simple ping/pong for connectivity testing
                peer_name = packet.get("name", "unknown")
                logger.info(f"PING from {peer_name} at {addr}")
                
                pong = json.dumps({
                    "type": "pong",
                    "server_time": time.time(),
                    "your_address": f"{addr[0]}:{addr[1]}"
                }).encode()
                self.transport.sendto(pong, addr)
                logger.info(f"Sent PONG to {addr}")
                
            else:
                logger.warning(f"Unknown type: {msg_type}")
            
            logger.info("=" * 70)
            logger.info("")
                    
        except json.JSONDecodeError as e:
            logger.error(f"JSON error from {addr}: {e}")
            logger.error(f"Data: {data[:500]}")
        except Exception as e:
            logger.error(f"Error from {addr}: {e}")
            import traceback
            traceback.print_exc()
    
    async def send_periodic_keepalives(self):
        """Send periodic keepalives to all registered peers to maintain NAT bindings"""
        await asyncio.sleep(5)  # Wait for initial registrations
        
        while True:
            try:
                current_time = time.time()
                stale_peers = []
                
                for peer_name, peer_data in list(self.peers.items()):
                    addr = peer_data["addr"]
                    last_seen = peer_data["last_seen"]
                    
                    # Remove stale peers (no activity for 60 seconds)
                    if current_time - last_seen > 60:
                        stale_peers.append(peer_name)
                        continue
                    
                    # Send keepalive ping
                    keepalive = json.dumps({
                        "type": "server_keepalive",
                        "server_time": current_time,
                        "peer_name": peer_name
                    }).encode()
                    
                    self.transport.sendto(keepalive, addr)
                    logger.debug(f"Sent keepalive to {peer_name} at {addr}")
                
                # Remove stale peers
                for peer_name in stale_peers:
                    logger.warning(f"Removing stale peer: {peer_name}")
                    del self.peers[peer_name]
                    
                    # Notify remaining peers about disconnection
                    for other_name, other_data in self.peers.items():
                        notification = json.dumps({
                            "type": "peer_left",
                            "peer_name": peer_name,
                            "peers": list(self.peers.keys())
                        }).encode()
                        self.transport.sendto(notification, other_data["addr"])
                        logger.info(f"Notified {other_name} about {peer_name} leaving")
                
                await asyncio.sleep(10)  # Send keepalive every 10 seconds
                
            except Exception as e:
                logger.error(f"Keepalive error: {e}")
                await asyncio.sleep(10)
