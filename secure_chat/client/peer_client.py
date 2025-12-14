import asyncio
import json
import logging
import os
import base64
import time
from crypto.manager import CryptoManager
from network.secure_channel import SecureChannel
from network.rate_limiter import RateLimiter
from network.protocol import SecurePeerProtocol
from config import MAX_PACKET_SIZE, MESSAGE_REPLAY_WINDOW

logger = logging.getLogger(__name__)


class SecurePeerClient:
    def __init__(self, name, listen_port, peer_ip, peer_port, private_key_path, public_key_path, relay_server=None):
        self.name = name
        self.listen_port = listen_port
        self.peer_ip = peer_ip
        self.peer_port = peer_port
        self.transport = None
        
        # RELAY SUPPORT (for signaling only)
        self.relay_server = relay_server  # (ip, port) tuple
        self.use_relay_for_signaling = bool(relay_server)
        self.relay_registered = False
        
        # DIRECT P2P CONNECTION
        self.peer_direct_addr = None  # Peer's public IP:port learned via relay
        self.direct_connection_established = False
        self.my_public_addr = None  # My public IP:port as seen by relay
        
        self.crypto_manager = CryptoManager(private_key_path, public_key_path)
        self.secure_channel = SecureChannel(self.crypto_manager)
        self.peer_addr = None
        self.peer_name = None
        self.is_initiator = False
        self.rate_limiter = RateLimiter()
        self.handshake_received = False
        self.keepalive_task = None
        self.handshake_task = None
        self.hole_punch_task = None

    async def start(self):
        """Start listening for incoming messages"""
        loop = asyncio.get_running_loop()
        self.transport, protocol = await loop.create_datagram_endpoint(
            lambda: SecurePeerProtocol(self),
            local_addr=('0.0.0.0', self.listen_port)
        )
        logger.info(f"✓ {self.name} listening on port {self.listen_port}")
        
        # Register with relay server if provided (for signaling)
        if self.relay_server:
            logger.info(f"✓ Registering with relay server {self.relay_server[0]}:{self.relay_server[1]}")
            logger.info(f"📡 Relay will be used for SIGNALING only (SIP-style)")
            await self.register_with_relay()
            await asyncio.sleep(2)  # Wait for registration
        
        logger.info(f"✓ Connecting to peer {self.peer_ip}:{self.peer_port}")
        logger.info(f"Initiating secure handshake...\n")
        
        self.is_initiator = True
        self.handshake_task = asyncio.create_task(self.connection_establishment())

    async def register_with_relay(self):
        """Register with relay server"""
        register_msg = json.dumps({
            "type": "register",
            "name": self.name
        }).encode()
        
        self.transport.sendto(register_msg, self.relay_server)
        logger.info(f"✓ Sent registration to relay server")
        
        # Send keepalive to relay every 15 seconds
        asyncio.create_task(self.relay_keepalive())

    async def relay_keepalive(self):
        """Keep relay registration alive"""
        await asyncio.sleep(5)  # First keepalive after 5 seconds
        
        while True:
            if self.relay_server:
                keepalive = json.dumps({
                    "type": "keepalive",
                    "name": self.name
                }).encode()
                self.transport.sendto(keepalive, self.relay_server)
            await asyncio.sleep(15)

    def send_via_relay(self, data):
        """Send packet via relay server (signaling only)"""
        if not self.relay_server:
            return
        
        target_name = "Bob" if self.name == "Alice" else "Alice"
        payload_str = data.decode('utf-8')
        
        relay_packet = json.dumps({
            "type": "relay",
            "target": target_name,
            "source": self.name,
            "payload": payload_str
        }).encode('utf-8')
        
        self.transport.sendto(relay_packet, self.relay_server)
        logger.debug(f"📤 Sent via RELAY (signaling) to {target_name}")

    def send_direct(self, data, addr):
        """Send packet directly to peer"""
        self.transport.sendto(data, addr)
        logger.debug(f"📤 Sent DIRECT to {addr}")

    async def connection_establishment(self):
        """
        SIP-style connection establishment:
        1. Try direct connection first
        2. If fails, use relay for signaling to exchange addresses
        3. Perform UDP hole punching
        4. Establish direct P2P connection
        """
        
        # Phase 1: Try direct connection (if we know peer's address)
        logger.info("🔄 Phase 1: Attempting direct connection...")
        direct_success = await self.try_direct_connection()
        
        if direct_success:
            logger.info("✓ Direct connection established!")
            return
        
        # Phase 2: Use relay for signaling
        if self.relay_server:
            logger.info("🔄 Phase 2: Using relay for signaling...")
            signaling_success = await self.signaling_via_relay()
            
            if not signaling_success:
                logger.error("✗ Signaling failed")
                return
            
            # Phase 3: UDP Hole Punching
            logger.info("🔄 Phase 3: Performing UDP hole punching...")
            hole_punch_success = await self.udp_hole_punching()
            
            if hole_punch_success:
                logger.info("✓ Direct P2P connection established via hole punching!")
                logger.info(f"✓ Media will flow DIRECTLY to {self.peer_direct_addr}")
                return
            else:
                logger.warning("⚠ Hole punching failed, falling back to relay for media")
        
        logger.error("✗ Failed to establish connection")

    async def try_direct_connection(self):
        """Try direct connection to peer's known address"""
        for attempt in range(10):
            await self.send_handshake_direct((self.peer_ip, self.peer_port))
            
            if attempt % 3 == 0:
                logger.info(f"🔄 Direct attempt {attempt + 1}/10...")
            
            await asyncio.sleep(0.5)
            
            if self.handshake_received:
                self.direct_connection_established = True
                return True
        
        return False

    async def signaling_via_relay(self):
        """Use relay to exchange connection information"""
        for attempt in range(20):
            if self.handshake_received:
                return True
            
            # Send handshake with our public address via relay
            await self.send_handshake_via_relay()
            
            if attempt % 5 == 0:
                logger.info(f"🔄 Signaling attempt {attempt + 1}/20...")
            
            await asyncio.sleep(1)
        
        return self.handshake_received

    async def udp_hole_punching(self):
        """
        Perform UDP hole punching to establish direct connection
        Both peers send packets to each other's public address simultaneously
        """
        if not self.peer_direct_addr:
            logger.error("✗ No peer address for hole punching")
            return False
        
        logger.info(f"🔨 Punching hole to {self.peer_direct_addr}...")
        
        # Send multiple punch packets
        for i in range(10):
            punch_packet = json.dumps({
                "type": "hole_punch",
                "from": self.name,
                "timestamp": time.time(),
                "sequence": i
            }).encode('utf-8')
            
            self.send_direct(punch_packet, self.peer_direct_addr)
            await asyncio.sleep(0.2)
            
            if self.direct_connection_established:
                return True
        
        # Wait a bit more for peer's punch packets
        await asyncio.sleep(2)
        
        return self.direct_connection_established

    async def send_handshake_direct(self, addr):
        """Send handshake directly to address"""
        handshake_data = {
            "name": self.name,
            "public_key": self.crypto_manager.get_public_key_pem(),
            "timestamp": time.time(),
            "listen_port": self.listen_port
        }
        handshake_json = json.dumps(handshake_data).encode()
        signature = self.crypto_manager.sign_message(handshake_json)
        
        handshake = json.dumps({
            "type": "handshake",
            "data": base64.b64encode(handshake_json).decode(),
            "signature": signature
        }).encode('utf-8')
        
        self.send_direct(handshake, addr)

    async def send_handshake_via_relay(self):
        """Send handshake via relay with our public address"""
        handshake_data = {
            "name": self.name,
            "public_key": self.crypto_manager.get_public_key_pem(),
            "timestamp": time.time(),
            "listen_port": self.listen_port,
            "my_public_addr": self.my_public_addr  # Include our public address
        }
        handshake_json = json.dumps(handshake_data).encode()
        signature = self.crypto_manager.sign_message(handshake_json)
        
        handshake = json.dumps({
            "type": "handshake",
            "data": base64.b64encode(handshake_json).decode(),
            "signature": signature
        }).encode('utf-8')
        
        self.send_via_relay(handshake)

    async def handle_handshake(self, message, addr, via_relay=False):
        """Handle incoming handshake"""
        if self.handshake_received:
            return
        
        try:
            handshake_json = base64.b64decode(message.get("data"))
            signature = message.get("signature")
            handshake_data = json.loads(handshake_json.decode())
            
            peer_name = handshake_data.get("name")
            peer_public_key = handshake_data.get("public_key")
            timestamp = handshake_data.get("timestamp")
            peer_public_addr = handshake_data.get("my_public_addr")
            
            if abs(time.time() - timestamp) > MESSAGE_REPLAY_WINDOW:
                logger.error("✗ Handshake timestamp too old")
                return
            
            if not self.crypto_manager.verify_peer_identity(peer_name, peer_public_key):
                logger.error("✗ Peer identity verification failed")
                return
            
            if not self.crypto_manager.verify_signature(handshake_json, signature, peer_public_key):
                logger.error("✗ Handshake signature verification failed")
                return
            
            # Store peer information
            self.peer_name = peer_name
            self.secure_channel.peer_public_key = peer_public_key
            self.handshake_received = True
            
            # Determine connection mode
            if via_relay:
                logger.info(f"✓ Received handshake from {peer_name} via RELAY")
                # Store peer's public address for hole punching
                if peer_public_addr:
                    self.peer_direct_addr = tuple(peer_public_addr.split(':'))
                    self.peer_direct_addr = (self.peer_direct_addr[0], int(self.peer_direct_addr[1]))
                    logger.info(f"✓ Learned peer's public address: {self.peer_direct_addr}")
            else:
                logger.info(f"✓ Received handshake from {peer_name} DIRECTLY")
                self.peer_direct_addr = addr
                self.direct_connection_established = True
            
            logger.info(f"✓ Verified {peer_name}'s identity")
            
            # Generate and send AES key
            aes_key = self.secure_channel.generate_aes_key()
            encrypted_aes_key = self.crypto_manager.encrypt_aes_key(aes_key, peer_public_key)
            
            key_exchange_data = {
                "name": self.name,
                "public_key": self.crypto_manager.get_public_key_pem(),
                "encrypted_aes_key": encrypted_aes_key,
                "timestamp": time.time(),
                "my_public_addr": self.my_public_addr
            }
            key_exchange_json = json.dumps(key_exchange_data).encode()
            signature = self.crypto_manager.sign_message(key_exchange_json)
            
            key_exchange = json.dumps({
                "type": "key_exchange",
                "data": base64.b64encode(key_exchange_json).decode(),
                "signature": signature
            }).encode('utf-8')
            
            # Send key exchange
            if via_relay and not self.direct_connection_established:
                self.send_via_relay(key_exchange)
                logger.info(f"✓ Sent encrypted AES key to {peer_name} via RELAY")
            else:
                self.send_direct(key_exchange, self.peer_direct_addr or addr)
                logger.info(f"✓ Sent encrypted AES key to {peer_name} DIRECTLY")
            
            self.secure_channel.handshake_complete = True
            logger.info(f"✓ Secure channel established!")
            
            if self.direct_connection_established:
                logger.info(f"✓ Connection mode: DIRECT P2P")
            else:
                logger.info(f"✓ Connection mode: Via RELAY (will attempt hole punching)")
            
            logger.info(f"\nType your message and press Enter:\n")
            
        except Exception as e:
            logger.error(f"✗ Handshake processing failed: {e}")
            import traceback
            traceback.print_exc()

    async def handle_key_exchange(self, message, addr, via_relay=False):
        """Handle incoming AES key"""
        try:
            key_exchange_json = base64.b64decode(message.get("data"))
            signature = message.get("signature")
            key_exchange_data = json.loads(key_exchange_json.decode())
            
            encrypted_aes_key = key_exchange_data.get("encrypted_aes_key")
            peer_name = key_exchange_data.get("name")
            peer_public_key = key_exchange_data.get("public_key")
            timestamp = key_exchange_data.get("timestamp")
            peer_public_addr = key_exchange_data.get("my_public_addr")
            
            if abs(time.time() - timestamp) > MESSAGE_REPLAY_WINDOW:
                logger.error("✗ Key exchange timestamp too old")
                return
            
            if not self.crypto_manager.verify_peer_identity(peer_name, peer_public_key):
                logger.error("✗ Peer identity verification failed")
                return
            
            if not self.crypto_manager.verify_signature(key_exchange_json, signature, peer_public_key):
                logger.error("✗ Key exchange signature verification failed")
                return
            
            self.peer_name = peer_name
            self.secure_channel.peer_public_key = peer_public_key
            self.handshake_received = True
            
            # Store peer's public address
            if via_relay and peer_public_addr:
                self.peer_direct_addr = tuple(peer_public_addr.split(':'))
                self.peer_direct_addr = (self.peer_direct_addr[0], int(self.peer_direct_addr[1]))
                logger.info(f"✓ Learned peer's public address: {self.peer_direct_addr}")
            elif not via_relay:
                self.peer_direct_addr = addr
                self.direct_connection_established = True
            
            aes_key = self.crypto_manager.decrypt_aes_key(encrypted_aes_key)
            self.secure_channel.aes_key = aes_key
            self.secure_channel.session_start = time.time()
            
            logger.info(f"✓ Decrypted AES key from {peer_name}")
            self.secure_channel.handshake_complete = True
            logger.info(f"✓ Secure channel established!")
            
            if self.direct_connection_established:
                logger.info(f"✓ Connection mode: DIRECT P2P")
            else:
                logger.info(f"✓ Connection mode: Via RELAY (will attempt hole punching)")
            
            logger.info(f"\nType your message and press Enter:\n")
            
        except Exception as e:
            logger.error(f"✗ Key exchange processing failed: {e}")
            import traceback
            traceback.print_exc()

    def handle_hole_punch(self, message, addr):
        """Handle hole punch packet"""
        try:
            from_peer = message.get("from")
            sequence = message.get("sequence")
            
            logger.info(f"🔨 Received hole punch #{sequence} from {from_peer} at {addr}")
            
            # Store peer's address and mark connection as established
            self.peer_direct_addr = addr
            self.direct_connection_established = True
            
            # Send acknowledgment
            ack = json.dumps({
                "type": "hole_punch_ack",
                "from": self.name,
                "timestamp": time.time()
            }).encode('utf-8')
            
            self.send_direct(ack, addr)
            logger.info(f"✓ Hole punching successful! Direct connection to {addr}")
            
        except Exception as e:
            logger.error(f"✗ Hole punch handling failed: {e}")

    def send_message(self, message):
        """Send encrypted message (always direct if possible)"""
        if not message.strip():
            return
        
        if not self.secure_channel.is_session_valid():
            logger.warning("⚠ Session expired")
            return
        
        if not self.secure_channel.handshake_complete:
            logger.warning("⚠ Secure channel not established yet")
            return
        
        try:
            plaintext = json.dumps({
                "from": self.name,
                "message": message,
                "timestamp": time.time(),
                "nonce": os.urandom(16).hex()
            }).encode()
            
            signature = self.crypto_manager.sign_message(plaintext)
            encrypted_message = self.secure_channel.encrypt_message(plaintext)
            
            packet = json.dumps({
                "type": "secure_message",
                "encrypted_message": encrypted_message,
                "signature": signature
            }).encode('utf-8')
            
            # Always try direct first
            if self.direct_connection_established and self.peer_direct_addr:
                self.send_direct(packet, self.peer_direct_addr)
                logger.info(f"{self.name}: {message} [DIRECT]")
            elif self.relay_server:
                self.send_via_relay(packet)
                logger.info(f"{self.name}: {message} [via RELAY]")
            else:
                logger.error("✗ No route to peer")
                
        except Exception as e:
            logger.error(f"✗ Error sending message: {e}")

    def receive_message(self, data, addr):
        """Handle incoming message"""
        if len(data) > MAX_PACKET_SIZE:
            return
        
        if not self.rate_limiter.allow(addr):
            return
        
        try:
            packet = json.loads(data.decode('utf-8'))
            if not isinstance(packet, dict) or "type" not in packet:
                return
            
            msg_type = packet.get("type")
            
            # Handle relay wrapper (signaling only)
            if msg_type == "relayed_packet":
                via_relay = packet.get("via_relay", False)
                from_peer = packet.get("from_peer", "unknown")
                payload_str = packet.get("payload")
                
                logger.debug(f"📥 Received relayed packet from {from_peer}")
                
                try:
                    actual_packet = json.loads(payload_str)
                    actual_type = actual_packet.get("type")
                    
                    if actual_type == "handshake":
                        asyncio.create_task(self.handle_handshake(actual_packet, addr, via_relay=True))
                    elif actual_type == "key_exchange":
                        asyncio.create_task(self.handle_key_exchange(actual_packet, addr, via_relay=True))
                    elif actual_type == "secure_message":
                        # Messages should come direct, but handle via relay as fallback
                        self.handle_secure_message(actual_packet, via_relay=True)
                    
                except json.JSONDecodeError:
                    logger.error("✗ Failed to decode relayed payload")
                return
            
            if msg_type == "register_ack":
                self.relay_registered = True
                # Extract our public address as seen by relay
                your_address = packet.get("your_address")
                if your_address:
                    self.my_public_addr = your_address
                    logger.info(f"✓ Registered with relay server (ACK received)")
                    logger.info(f"✓ My public address: {your_address}")
                return
            
            if msg_type == "peer_list":
                peers = packet.get("peers", [])
                logger.info(f"✓ Available peers on relay: {', '.join(peers)}")
                return
            
            if msg_type == "peer_joined":
                peer_name = packet.get("peer_name")
                logger.info(f"✓ Peer joined relay: {peer_name}")
                return
            
            if msg_type == "peer_left":
                peer_name = packet.get("peer_name")
                logger.warning(f"⚠ Peer left relay: {peer_name}")
                return
            
            if msg_type == "hole_punch":
                self.handle_hole_punch(packet, addr)
                return
            
            if msg_type == "hole_punch_ack":
                logger.info(f"✓ Received hole punch ACK from {addr}")
                self.peer_direct_addr = addr
                self.direct_connection_established = True
                return
            
            if msg_type == "handshake":
                asyncio.create_task(self.handle_handshake(packet, addr, via_relay=False))
            elif msg_type == "key_exchange":
                asyncio.create_task(self.handle_key_exchange(packet, addr, via_relay=False))
            elif msg_type == "secure_message":
                self.handle_secure_message(packet, via_relay=False)
                    
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.error(f"✗ Invalid packet format: {e}")
        except Exception as e:
            logger.error(f"✗ Error processing packet: {e}")
            import traceback
            traceback.print_exc()

    def handle_secure_message(self, packet, via_relay=False):
        """Handle secure message"""
        if not self.secure_channel.is_session_valid():
            return
        
        encrypted_message = packet.get("encrypted_message")
        signature = packet.get("signature")
        
        try:
            plaintext = self.secure_channel.decrypt_message(encrypted_message)
            
            if not self.secure_channel.peer_public_key:
                logger.error("✗ No peer public key")
                return
            
            if not self.crypto_manager.verify_signature(plaintext, signature, self.secure_channel.peer_public_key):
                logger.error("✗ Invalid signature")
                return
            
            msg = json.loads(plaintext.decode())
            timestamp = msg.get("timestamp")
            nonce = msg.get("nonce")
            
            if not timestamp or not nonce:
                return
            
            if abs(time.time() - timestamp) > MESSAGE_REPLAY_WINDOW:
                return
            
            if nonce in self.secure_channel.seen_nonces:
                logger.warning("⚠ Replay attack detected")
                return
            
            self.secure_channel.seen_nonces.add(nonce)
            self.secure_channel.cleanup_old_nonces()
            
            sender = msg.get("from", "Unknown")
            content = msg.get("message", "")
            
            route = "[DIRECT]" if not via_relay else "[via RELAY]"
            logger.info(f"{sender}: {content} {route}")
            
        except Exception as e:
            logger.error(f"✗ Message processing failed: {e}")
