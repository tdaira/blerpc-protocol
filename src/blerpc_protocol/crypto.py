"""E2E encryption for blerpc using X25519, Ed25519, AES-128-GCM, HKDF-SHA256."""

from __future__ import annotations

import os
import struct
from collections.abc import Awaitable, Callable

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Direction bytes for nonce construction
DIRECTION_C2P = 0x00
DIRECTION_P2C = 0x01

# Confirmation plaintexts
CONFIRM_CENTRAL = b"BLERPC_CONFIRM_C"
CONFIRM_PERIPHERAL = b"BLERPC_CONFIRM_P"

# Key exchange step constants
KEY_EXCHANGE_STEP1 = 0x01
KEY_EXCHANGE_STEP2 = 0x02
KEY_EXCHANGE_STEP3 = 0x03
KEY_EXCHANGE_STEP4 = 0x04


class BlerpcCrypto:
    """Cryptographic operations for blerpc E2E encryption."""

    @staticmethod
    def generate_x25519_keypair() -> tuple[X25519PrivateKey, bytes]:
        """Generate an X25519 key pair.

        Returns (private_key, public_key_bytes_32).
        """
        private_key = X25519PrivateKey.generate()
        public_bytes = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return private_key, public_bytes

    @staticmethod
    def x25519_public_bytes(private_key: X25519PrivateKey) -> bytes:
        """Get the raw 32-byte public key from a private key."""
        return private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    @staticmethod
    def x25519_shared_secret(
        private_key: X25519PrivateKey, peer_public_bytes: bytes
    ) -> bytes:
        """Compute X25519 shared secret (32 bytes)."""
        peer_public = X25519PublicKey.from_public_bytes(peer_public_bytes)
        return private_key.exchange(peer_public)

    @staticmethod
    def derive_session_key(
        shared_secret: bytes,
        central_pubkey: bytes,
        peripheral_pubkey: bytes,
    ) -> bytes:
        """Derive 16-byte AES-128 session key using HKDF-SHA256.

        salt = central_pubkey || peripheral_pubkey (64 bytes)
        info = b"blerpc-session-key"
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=16,
            salt=central_pubkey + peripheral_pubkey,
            info=b"blerpc-session-key",
        )
        return hkdf.derive(shared_secret)

    @staticmethod
    def generate_ed25519_keypair() -> tuple[Ed25519PrivateKey, bytes]:
        """Generate an Ed25519 key pair.

        Returns (private_key, public_key_bytes_32).
        """
        private_key = Ed25519PrivateKey.generate()
        public_bytes = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return private_key, public_bytes

    @staticmethod
    def ed25519_public_bytes(private_key: Ed25519PrivateKey) -> bytes:
        """Get the raw 32-byte public key from a private key."""
        return private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    @staticmethod
    def ed25519_sign(private_key: Ed25519PrivateKey, message: bytes) -> bytes:
        """Sign a message with Ed25519. Returns 64-byte signature."""
        return private_key.sign(message)

    @staticmethod
    def ed25519_verify(
        public_key_bytes: bytes, message: bytes, signature: bytes
    ) -> bool:
        """Verify an Ed25519 signature. Returns True if valid."""
        try:
            public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            public_key.verify(signature, message)
            return True
        except Exception:
            return False

    @staticmethod
    def ed25519_private_from_bytes(data: bytes) -> Ed25519PrivateKey:
        """Load Ed25519 private key from raw 32-byte seed."""
        return Ed25519PrivateKey.from_private_bytes(data)

    @staticmethod
    def x25519_private_from_bytes(data: bytes) -> X25519PrivateKey:
        """Load X25519 private key from raw 32 bytes."""
        return X25519PrivateKey.from_private_bytes(data)

    @staticmethod
    def _build_nonce(counter: int, direction: int) -> bytes:
        """Build 12-byte AES-GCM nonce: counter(4B) || direction(1B) || zeros(7B)."""
        return struct.pack("<IB", counter, direction) + b"\x00" * 7

    @staticmethod
    def encrypt_command(
        session_key: bytes, counter: int, direction: int, plaintext: bytes
    ) -> bytes:
        """Encrypt a command payload.

        Returns: [counter:4BLE][ciphertext:NB][tag:16B]
        """
        nonce = BlerpcCrypto._build_nonce(counter, direction)
        aesgcm = AESGCM(session_key)
        ct_and_tag = aesgcm.encrypt(nonce, plaintext, None)
        return struct.pack("<I", counter) + ct_and_tag

    @staticmethod
    def decrypt_command(
        session_key: bytes, direction: int, data: bytes
    ) -> tuple[int, bytes]:
        """Decrypt a command payload.

        Input: [counter:4BLE][ciphertext:NB][tag:16B]
        Returns: (counter, plaintext)
        """
        if len(data) < 20:
            raise ValueError(f"Encrypted payload too short: {len(data)}")
        counter = struct.unpack_from("<I", data, 0)[0]
        ct_and_tag = data[4:]
        nonce = BlerpcCrypto._build_nonce(counter, direction)
        aesgcm = AESGCM(session_key)
        plaintext = aesgcm.decrypt(nonce, ct_and_tag, None)
        return counter, plaintext

    @staticmethod
    def encrypt_confirmation(session_key: bytes, message: bytes) -> bytes:
        """Encrypt a confirmation message for key exchange step 3/4.

        Returns: [nonce:12B][ciphertext:16B][tag:16B] = 44 bytes
        """
        nonce = os.urandom(12)
        aesgcm = AESGCM(session_key)
        ct_and_tag = aesgcm.encrypt(nonce, message, None)
        return nonce + ct_and_tag

    @staticmethod
    def decrypt_confirmation(session_key: bytes, data: bytes) -> bytes:
        """Decrypt a confirmation message from key exchange step 3/4.

        Input: [nonce:12B][ciphertext:16B][tag:16B] = 44 bytes
        Returns: plaintext (16 bytes)
        """
        if len(data) < 44:
            raise ValueError(f"Confirmation too short: {len(data)}")
        nonce = data[:12]
        ct_and_tag = data[12:]
        aesgcm = AESGCM(session_key)
        return aesgcm.decrypt(nonce, ct_and_tag, None)

    @staticmethod
    def build_step1_payload(central_x25519_pubkey: bytes) -> bytes:
        """Build KEY_EXCHANGE step 1 payload (33 bytes).

        [step:u8=0x01][central_x25519_pubkey:32B]
        """
        return bytes([KEY_EXCHANGE_STEP1]) + central_x25519_pubkey

    @staticmethod
    def parse_step1_payload(data: bytes) -> bytes:
        """Parse KEY_EXCHANGE step 1 payload.

        Returns central_x25519_pubkey (32 bytes).
        """
        if len(data) < 33 or data[0] != KEY_EXCHANGE_STEP1:
            raise ValueError("Invalid step 1 payload")
        return data[1:33]

    @staticmethod
    def build_step2_payload(
        peripheral_x25519_pubkey: bytes,
        ed25519_signature: bytes,
        peripheral_ed25519_pubkey: bytes,
    ) -> bytes:
        """Build KEY_EXCHANGE step 2 payload (129 bytes).

        [step:u8=0x02][peripheral_x25519_pubkey:32B][ed25519_signature:64B]
        [peripheral_ed25519_pubkey:32B]
        """
        return (
            bytes([KEY_EXCHANGE_STEP2])
            + peripheral_x25519_pubkey
            + ed25519_signature
            + peripheral_ed25519_pubkey
        )

    @staticmethod
    def parse_step2_payload(
        data: bytes,
    ) -> tuple[bytes, bytes, bytes]:
        """Parse KEY_EXCHANGE step 2 payload.

        Returns (peripheral_x25519_pubkey, ed25519_signature,
                 peripheral_ed25519_pubkey).
        """
        if len(data) < 129 or data[0] != KEY_EXCHANGE_STEP2:
            raise ValueError("Invalid step 2 payload")
        peripheral_x25519_pubkey = data[1:33]
        ed25519_signature = data[33:97]
        peripheral_ed25519_pubkey = data[97:129]
        return peripheral_x25519_pubkey, ed25519_signature, peripheral_ed25519_pubkey

    @staticmethod
    def build_step3_payload(confirmation_encrypted: bytes) -> bytes:
        """Build KEY_EXCHANGE step 3 payload (45 bytes).

        [step:u8=0x03][nonce:12B][ciphertext:16B][tag:16B]
        """
        return bytes([KEY_EXCHANGE_STEP3]) + confirmation_encrypted

    @staticmethod
    def parse_step3_payload(data: bytes) -> bytes:
        """Parse KEY_EXCHANGE step 3 payload.

        Returns the encrypted confirmation (44 bytes).
        """
        if len(data) < 45 or data[0] != KEY_EXCHANGE_STEP3:
            raise ValueError("Invalid step 3 payload")
        return data[1:45]

    @staticmethod
    def build_step4_payload(confirmation_encrypted: bytes) -> bytes:
        """Build KEY_EXCHANGE step 4 payload (45 bytes).

        [step:u8=0x04][nonce:12B][ciphertext:16B][tag:16B]
        """
        return bytes([KEY_EXCHANGE_STEP4]) + confirmation_encrypted

    @staticmethod
    def parse_step4_payload(data: bytes) -> bytes:
        """Parse KEY_EXCHANGE step 4 payload.

        Returns the encrypted confirmation (44 bytes).
        """
        if len(data) < 45 or data[0] != KEY_EXCHANGE_STEP4:
            raise ValueError("Invalid step 4 payload")
        return data[1:45]


class BlerpcCryptoSession:
    """Encrypt/decrypt with counter management and replay detection."""

    def __init__(self, session_key: bytes, is_central: bool):
        self._session_key = session_key
        self._tx_counter = 0
        self._rx_counter = 0
        self._rx_first_done = False
        self._tx_direction = DIRECTION_C2P if is_central else DIRECTION_P2C
        self._rx_direction = DIRECTION_P2C if is_central else DIRECTION_C2P

    def encrypt(self, plaintext: bytes) -> bytes:
        encrypted = BlerpcCrypto.encrypt_command(
            self._session_key, self._tx_counter, self._tx_direction, plaintext
        )
        self._tx_counter += 1
        return encrypted

    def decrypt(self, data: bytes) -> bytes:
        counter, plaintext = BlerpcCrypto.decrypt_command(
            self._session_key, self._rx_direction, data
        )
        if self._rx_first_done and counter <= self._rx_counter:
            raise RuntimeError(f"Replay detected: counter={counter}")
        self._rx_counter = counter
        self._rx_first_done = True
        return plaintext


class CentralKeyExchange:
    """Central-side key exchange state machine.

    Usage:
        kx = CentralKeyExchange()
        step1_payload = kx.start()                          # send to peripheral
        step3_payload = kx.process_step2(step2_payload)     # send to peripheral
        session       = kx.finish(step4_payload)           # BlerpcCryptoSession
    """

    def __init__(self) -> None:
        self._x25519_privkey: X25519PrivateKey | None = None
        self._x25519_pubkey: bytes | None = None
        self._session_key: bytes | None = None

    def start(self) -> bytes:
        """Generate ephemeral X25519 keypair and return step 1 payload."""
        self._x25519_privkey, self._x25519_pubkey = (
            BlerpcCrypto.generate_x25519_keypair()
        )
        return BlerpcCrypto.build_step1_payload(self._x25519_pubkey)

    def process_step2(
        self,
        step2_payload: bytes,
        verify_key_cb: Callable[[bytes], bool] | None = None,
    ) -> bytes:
        """Parse step 2, verify signature, derive session key, return step 3 payload.

        Args:
            step2_payload: Raw step 2 payload from peripheral.
            verify_key_cb: Optional callback receiving the peripheral's Ed25519 public
                key (32 bytes). Return True to accept, False to reject (e.g. TOFU).
                If None, any valid signature is accepted.

        Raises:
            ValueError: If signature verification fails or verify_key_cb rejects.
        """
        periph_x25519_pub, signature, periph_ed25519_pub = (
            BlerpcCrypto.parse_step2_payload(step2_payload)
        )

        sign_msg = self._x25519_pubkey + periph_x25519_pub
        if not BlerpcCrypto.ed25519_verify(periph_ed25519_pub, sign_msg, signature):
            raise ValueError("Ed25519 signature verification failed")

        if verify_key_cb is not None and not verify_key_cb(periph_ed25519_pub):
            raise ValueError("Peripheral key rejected by verify callback")

        shared_secret = BlerpcCrypto.x25519_shared_secret(
            self._x25519_privkey, periph_x25519_pub
        )
        self._session_key = BlerpcCrypto.derive_session_key(
            shared_secret, self._x25519_pubkey, periph_x25519_pub
        )

        encrypted_confirm = BlerpcCrypto.encrypt_confirmation(
            self._session_key, CONFIRM_CENTRAL
        )
        return BlerpcCrypto.build_step3_payload(encrypted_confirm)

    def finish(self, step4_payload: bytes) -> BlerpcCryptoSession:
        """Parse step 4, verify peripheral confirmation, return session.

        Raises:
            ValueError: If confirmation verification fails.
        """
        encrypted_periph = BlerpcCrypto.parse_step4_payload(step4_payload)
        plaintext = BlerpcCrypto.decrypt_confirmation(
            self._session_key, encrypted_periph
        )
        if plaintext != CONFIRM_PERIPHERAL:
            raise ValueError("Peripheral confirmation mismatch")

        return BlerpcCryptoSession(self._session_key, is_central=True)


class PeripheralKeyExchange:
    """Peripheral-side key exchange state machine.

    Usage:
        kx = PeripheralKeyExchange(x25519_privkey, ed25519_privkey)
        step2_payload          = kx.process_step1(step1_payload)  # send to central
        step4_payload, session = kx.process_step3(step3_payload)  # send + session
    """

    def __init__(
        self,
        x25519_privkey: X25519PrivateKey,
        ed25519_privkey: Ed25519PrivateKey,
    ) -> None:
        self._x25519_privkey = x25519_privkey
        self._x25519_pubkey = BlerpcCrypto.x25519_public_bytes(x25519_privkey)
        self._ed25519_privkey = ed25519_privkey
        self._ed25519_pubkey = BlerpcCrypto.ed25519_public_bytes(ed25519_privkey)
        self._session_key: bytes | None = None

    def process_step1(self, step1_payload: bytes) -> bytes:
        """Parse step 1, sign, derive session key, return step 2 payload."""
        central_x25519_pubkey = BlerpcCrypto.parse_step1_payload(step1_payload)

        sign_msg = central_x25519_pubkey + self._x25519_pubkey
        signature = BlerpcCrypto.ed25519_sign(self._ed25519_privkey, sign_msg)

        shared_secret = BlerpcCrypto.x25519_shared_secret(
            self._x25519_privkey, central_x25519_pubkey
        )
        self._session_key = BlerpcCrypto.derive_session_key(
            shared_secret, central_x25519_pubkey, self._x25519_pubkey
        )

        return BlerpcCrypto.build_step2_payload(
            self._x25519_pubkey, signature, self._ed25519_pubkey
        )

    def process_step3(self, step3_payload: bytes) -> tuple[bytes, BlerpcCryptoSession]:
        """Parse step 3, verify confirmation, return (step4_payload, session).

        Raises:
            ValueError: If central confirmation verification fails.
        """
        encrypted = BlerpcCrypto.parse_step3_payload(step3_payload)
        plaintext = BlerpcCrypto.decrypt_confirmation(self._session_key, encrypted)
        if plaintext != CONFIRM_CENTRAL:
            raise ValueError("Central confirmation mismatch")

        encrypted_confirm = BlerpcCrypto.encrypt_confirmation(
            self._session_key, CONFIRM_PERIPHERAL
        )
        step4 = BlerpcCrypto.build_step4_payload(encrypted_confirm)
        session = BlerpcCryptoSession(self._session_key, is_central=False)

        return step4, session

    def handle_step(
        self, payload: bytes
    ) -> tuple[bytes, BlerpcCryptoSession | None]:
        """Dispatch a key exchange payload by step byte.

        Returns (response_payload, session_or_none).
        Session is returned only after step 3 completes successfully.

        Raises:
            ValueError: If the step byte is invalid or processing fails.
        """
        if len(payload) < 1:
            raise ValueError("Empty key exchange payload")

        step = payload[0]
        if step == KEY_EXCHANGE_STEP1:
            return self.process_step1(payload), None
        elif step == KEY_EXCHANGE_STEP3:
            step4, session = self.process_step3(payload)
            return step4, session
        else:
            raise ValueError(f"Invalid key exchange step: 0x{step:02x}")


async def central_perform_key_exchange(
    send: Callable[[bytes], Awaitable[None]],
    receive: Callable[[], Awaitable[bytes]],
    verify_key_cb: Callable[[bytes], bool] | None = None,
) -> BlerpcCryptoSession:
    """Perform the 4-step central key exchange using send/receive callbacks.

    Args:
        send: Async callback to send a key exchange payload.
        receive: Async callback to receive a key exchange payload.
        verify_key_cb: Optional callback to verify peripheral's Ed25519 public key.

    Returns:
        An established BlerpcCryptoSession.

    Raises:
        ValueError: If any step of the key exchange fails.
    """
    kx = CentralKeyExchange()

    # Step 1: Send central's ephemeral public key
    step1 = kx.start()
    await send(step1)

    # Step 2: Receive peripheral's response
    step2 = await receive()

    # Step 2 -> Step 3: Verify and produce confirmation
    step3 = kx.process_step2(step2, verify_key_cb=verify_key_cb)
    await send(step3)

    # Step 4: Receive peripheral's confirmation
    step4 = await receive()

    return kx.finish(step4)
