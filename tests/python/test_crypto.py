"""Tests for blerpc E2E encryption module."""

import struct

import pytest
from cryptography.hazmat.primitives import serialization

from blerpc_protocol.container import (
    Container,
    CAPABILITY_FLAG_ENCRYPTION_SUPPORTED,
    ControlCmd,
    make_capabilities_request,
    make_capabilities_response,
    make_key_exchange,
)
from blerpc_protocol.crypto import (
    CONFIRM_CENTRAL,
    CONFIRM_PERIPHERAL,
    DIRECTION_C2P,
    DIRECTION_P2C,
    KEY_EXCHANGE_STEP1,
    KEY_EXCHANGE_STEP2,
    KEY_EXCHANGE_STEP3,
    KEY_EXCHANGE_STEP4,
    BlerpcCrypto,
    BlerpcCryptoSession,
    CentralKeyExchange,
    PeripheralKeyExchange,
)


class TestControlCmdKeyExchange:
    def test_key_exchange_enum_value(self):
        assert ControlCmd.KEY_EXCHANGE == 0x6

    def test_make_key_exchange_container(self):
        payload = b"\x01" + b"\x00" * 32
        c = make_key_exchange(transaction_id=5, payload=payload)
        assert c.control_cmd == ControlCmd.KEY_EXCHANGE
        assert c.payload == payload

    def test_key_exchange_roundtrip(self):
        payload = b"\x02" + b"\xAA" * 128
        c = make_key_exchange(transaction_id=10, payload=payload)
        data = c.serialize()
        c2 = Container.deserialize(data)
        assert c2.control_cmd == ControlCmd.KEY_EXCHANGE
        assert c2.payload == payload


class TestCapabilitiesFlags:
    def test_encryption_flag_constant(self):
        assert CAPABILITY_FLAG_ENCRYPTION_SUPPORTED == 0x0001

    def test_capabilities_request_6_bytes(self):
        c = make_capabilities_request(
            transaction_id=1,
            max_request_payload_size=1024,
            max_response_payload_size=2048,
            flags=CAPABILITY_FLAG_ENCRYPTION_SUPPORTED,
        )
        assert len(c.payload) == 6
        max_req, max_resp, flags = struct.unpack("<HHH", c.payload)
        assert max_req == 1024
        assert max_resp == 2048
        assert flags == CAPABILITY_FLAG_ENCRYPTION_SUPPORTED

    def test_capabilities_response_6_bytes(self):
        c = make_capabilities_response(
            transaction_id=2,
            max_request_payload_size=4096,
            max_response_payload_size=65535,
            flags=CAPABILITY_FLAG_ENCRYPTION_SUPPORTED,
        )
        assert len(c.payload) == 6
        max_req, max_resp, flags = struct.unpack("<HHH", c.payload)
        assert max_req == 4096
        assert max_resp == 65535
        assert flags == 1

    def test_capabilities_request_default_flags_zero(self):
        c = make_capabilities_request(transaction_id=3)
        _, _, flags = struct.unpack("<HHH", c.payload)
        assert flags == 0

    def test_capabilities_response_default_flags_zero(self):
        c = make_capabilities_response(
            transaction_id=4,
            max_request_payload_size=100,
            max_response_payload_size=200,
        )
        _, _, flags = struct.unpack("<HHH", c.payload)
        assert flags == 0


class TestX25519:
    def test_keygen_produces_32_byte_keys(self):
        privkey, pubkey = BlerpcCrypto.generate_x25519_keypair()
        pub_bytes = BlerpcCrypto.x25519_public_bytes(privkey)
        assert len(pubkey) == 32
        assert len(pub_bytes) == 32
        assert pubkey == pub_bytes

    def test_shared_secret_agreement(self):
        priv_a, pub_a = BlerpcCrypto.generate_x25519_keypair()
        priv_b, pub_b = BlerpcCrypto.generate_x25519_keypair()

        secret_a = BlerpcCrypto.x25519_shared_secret(priv_a, pub_b)
        secret_b = BlerpcCrypto.x25519_shared_secret(priv_b, pub_a)

        assert len(secret_a) == 32
        assert secret_a == secret_b

    def test_different_keys_different_secrets(self):
        priv_a, pub_a = BlerpcCrypto.generate_x25519_keypair()
        priv_b, pub_b = BlerpcCrypto.generate_x25519_keypair()
        priv_c, pub_c = BlerpcCrypto.generate_x25519_keypair()

        secret_ab = BlerpcCrypto.x25519_shared_secret(priv_a, pub_b)
        secret_ac = BlerpcCrypto.x25519_shared_secret(priv_a, pub_c)

        assert secret_ab != secret_ac


class TestEd25519:
    def test_sign_verify_roundtrip(self):
        privkey, pubkey = BlerpcCrypto.generate_ed25519_keypair()
        message = b"test message"
        signature = BlerpcCrypto.ed25519_sign(privkey, message)

        assert len(signature) == 64
        assert BlerpcCrypto.ed25519_verify(pubkey, message, signature)

    def test_verify_wrong_message_fails(self):
        privkey, pubkey = BlerpcCrypto.generate_ed25519_keypair()
        signature = BlerpcCrypto.ed25519_sign(privkey, b"correct message")
        assert not BlerpcCrypto.ed25519_verify(pubkey, b"wrong message", signature)

    def test_verify_wrong_key_fails(self):
        priv1, pub1 = BlerpcCrypto.generate_ed25519_keypair()
        _, pub2 = BlerpcCrypto.generate_ed25519_keypair()

        signature = BlerpcCrypto.ed25519_sign(priv1, b"test")
        assert BlerpcCrypto.ed25519_verify(pub1, b"test", signature)
        assert not BlerpcCrypto.ed25519_verify(pub2, b"test", signature)

    def test_load_from_bytes(self):
        privkey, pubkey = BlerpcCrypto.generate_ed25519_keypair()
        priv_bytes = privkey.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        loaded = BlerpcCrypto.ed25519_private_from_bytes(priv_bytes)
        loaded_pub = BlerpcCrypto.ed25519_public_bytes(loaded)
        assert loaded_pub == pubkey


class TestSessionKeyDerivation:
    def test_derive_produces_16_bytes(self):
        shared = b"\x42" * 32
        central_pub = b"\xAA" * 32
        peripheral_pub = b"\xBB" * 32
        key = BlerpcCrypto.derive_session_key(shared, central_pub, peripheral_pub)
        assert len(key) == 16

    def test_same_inputs_same_key(self):
        shared = b"\x42" * 32
        c_pub = b"\xAA" * 32
        p_pub = b"\xBB" * 32
        key1 = BlerpcCrypto.derive_session_key(shared, c_pub, p_pub)
        key2 = BlerpcCrypto.derive_session_key(shared, c_pub, p_pub)
        assert key1 == key2

    def test_different_pubkeys_different_key(self):
        shared = b"\x42" * 32
        c_pub_a = b"\xAA" * 32
        c_pub_b = b"\xCC" * 32
        p_pub = b"\xBB" * 32
        key1 = BlerpcCrypto.derive_session_key(shared, c_pub_a, p_pub)
        key2 = BlerpcCrypto.derive_session_key(shared, c_pub_b, p_pub)
        assert key1 != key2


class TestAesGcmEncryptDecrypt:
    def test_encrypt_decrypt_command_roundtrip(self):
        key = b"\x01" * 16
        plaintext = b"Hello, blerpc!"
        encrypted = BlerpcCrypto.encrypt_command(key, 0, DIRECTION_C2P, plaintext)

        # Encrypted format: counter(4) + ciphertext(N) + tag(16)
        assert len(encrypted) == 4 + len(plaintext) + 16

        counter, decrypted = BlerpcCrypto.decrypt_command(key, DIRECTION_C2P, encrypted)
        assert counter == 0
        assert decrypted == plaintext

    def test_different_directions_produce_different_ciphertext(self):
        key = b"\x01" * 16
        plaintext = b"test"
        enc_c2p = BlerpcCrypto.encrypt_command(key, 0, DIRECTION_C2P, plaintext)
        enc_p2c = BlerpcCrypto.encrypt_command(key, 0, DIRECTION_P2C, plaintext)
        assert enc_c2p != enc_p2c

    def test_wrong_direction_fails_decrypt(self):
        key = b"\x01" * 16
        encrypted = BlerpcCrypto.encrypt_command(key, 0, DIRECTION_C2P, b"test")
        with pytest.raises(Exception):
            BlerpcCrypto.decrypt_command(key, DIRECTION_P2C, encrypted)

    def test_wrong_key_fails_decrypt(self):
        key1 = b"\x01" * 16
        key2 = b"\x02" * 16
        encrypted = BlerpcCrypto.encrypt_command(key1, 0, DIRECTION_C2P, b"test")
        with pytest.raises(Exception):
            BlerpcCrypto.decrypt_command(key2, DIRECTION_C2P, encrypted)

    def test_counter_embedded_in_output(self):
        key = b"\x01" * 16
        encrypted = BlerpcCrypto.encrypt_command(key, 42, DIRECTION_C2P, b"data")
        counter = struct.unpack_from("<I", encrypted, 0)[0]
        assert counter == 42

    def test_empty_plaintext(self):
        key = b"\x01" * 16
        encrypted = BlerpcCrypto.encrypt_command(key, 0, DIRECTION_C2P, b"")
        counter, decrypted = BlerpcCrypto.decrypt_command(key, DIRECTION_C2P, encrypted)
        assert decrypted == b""

    def test_large_plaintext(self):
        key = b"\x01" * 16
        plaintext = b"\xFF" * 10000
        encrypted = BlerpcCrypto.encrypt_command(key, 0, DIRECTION_C2P, plaintext)
        counter, decrypted = BlerpcCrypto.decrypt_command(key, DIRECTION_C2P, encrypted)
        assert decrypted == plaintext

    def test_decrypt_too_short_raises(self):
        key = b"\x01" * 16
        with pytest.raises(ValueError, match="too short"):
            BlerpcCrypto.decrypt_command(key, DIRECTION_C2P, b"\x00" * 19)


class TestConfirmation:
    def test_encrypt_decrypt_confirmation_roundtrip(self):
        key = b"\x01" * 16
        encrypted = BlerpcCrypto.encrypt_confirmation(key, CONFIRM_CENTRAL)
        assert len(encrypted) == 44  # 12 nonce + 16 ct + 16 tag

        plaintext = BlerpcCrypto.decrypt_confirmation(key, encrypted)
        assert plaintext == CONFIRM_CENTRAL

    def test_different_messages_different_output(self):
        key = b"\x01" * 16
        enc_c = BlerpcCrypto.encrypt_confirmation(key, CONFIRM_CENTRAL)
        enc_p = BlerpcCrypto.encrypt_confirmation(key, CONFIRM_PERIPHERAL)
        # Different due to random nonce + different plaintext
        assert enc_c != enc_p

    def test_wrong_key_fails(self):
        key1 = b"\x01" * 16
        key2 = b"\x02" * 16
        encrypted = BlerpcCrypto.encrypt_confirmation(key1, CONFIRM_CENTRAL)
        with pytest.raises(Exception):
            BlerpcCrypto.decrypt_confirmation(key2, encrypted)


class TestStepPayloads:
    def test_step1_build_parse(self):
        pubkey = b"\xAA" * 32
        payload = BlerpcCrypto.build_step1_payload(pubkey)
        assert len(payload) == 33
        assert payload[0] == KEY_EXCHANGE_STEP1
        parsed = BlerpcCrypto.parse_step1_payload(payload)
        assert parsed == pubkey

    def test_step2_build_parse(self):
        x25519_pub = b"\xAA" * 32
        signature = b"\xBB" * 64
        ed25519_pub = b"\xCC" * 32
        payload = BlerpcCrypto.build_step2_payload(x25519_pub, signature, ed25519_pub)
        assert len(payload) == 129
        assert payload[0] == KEY_EXCHANGE_STEP2
        p_x25519, p_sig, p_ed25519 = BlerpcCrypto.parse_step2_payload(payload)
        assert p_x25519 == x25519_pub
        assert p_sig == signature
        assert p_ed25519 == ed25519_pub

    def test_step3_build_parse(self):
        encrypted = b"\xDD" * 44
        payload = BlerpcCrypto.build_step3_payload(encrypted)
        assert len(payload) == 45
        assert payload[0] == KEY_EXCHANGE_STEP3
        parsed = BlerpcCrypto.parse_step3_payload(payload)
        assert parsed == encrypted

    def test_step4_build_parse(self):
        encrypted = b"\xEE" * 44
        payload = BlerpcCrypto.build_step4_payload(encrypted)
        assert len(payload) == 45
        assert payload[0] == KEY_EXCHANGE_STEP4
        parsed = BlerpcCrypto.parse_step4_payload(payload)
        assert parsed == encrypted

    def test_step1_invalid_short(self):
        with pytest.raises(ValueError, match="Invalid step 1"):
            BlerpcCrypto.parse_step1_payload(b"\x01" + b"\x00" * 10)

    def test_step1_invalid_step_byte(self):
        with pytest.raises(ValueError, match="Invalid step 1"):
            BlerpcCrypto.parse_step1_payload(b"\x02" + b"\x00" * 32)

    def test_step2_invalid_short(self):
        with pytest.raises(ValueError, match="Invalid step 2"):
            BlerpcCrypto.parse_step2_payload(b"\x02" + b"\x00" * 50)


class TestFullKeyExchangeFlow:
    """Test the complete 4-step key exchange between simulated central and peripheral."""

    def test_full_handshake(self):
        # Peripheral's long-term keys
        periph_ed_priv, periph_ed_pub = BlerpcCrypto.generate_ed25519_keypair()
        periph_x_priv, periph_x_pub = BlerpcCrypto.generate_x25519_keypair()

        # Step 1: Central generates ephemeral keypair
        central_x_priv, central_x_pub = BlerpcCrypto.generate_x25519_keypair()
        step1 = BlerpcCrypto.build_step1_payload(central_x_pub)
        parsed_central_pub = BlerpcCrypto.parse_step1_payload(step1)
        assert parsed_central_pub == central_x_pub

        # Step 2: Peripheral signs and responds
        sign_msg = central_x_pub + periph_x_pub
        signature = BlerpcCrypto.ed25519_sign(periph_ed_priv, sign_msg)
        step2 = BlerpcCrypto.build_step2_payload(periph_x_pub, signature, periph_ed_pub)

        # Central parses and verifies
        p_x_pub, p_sig, p_ed_pub = BlerpcCrypto.parse_step2_payload(step2)
        assert p_x_pub == periph_x_pub
        assert BlerpcCrypto.ed25519_verify(p_ed_pub, sign_msg, p_sig)

        # Both derive shared secret and session key
        shared_c = BlerpcCrypto.x25519_shared_secret(central_x_priv, periph_x_pub)
        shared_p = BlerpcCrypto.x25519_shared_secret(periph_x_priv, central_x_pub)
        assert shared_c == shared_p

        session_key_c = BlerpcCrypto.derive_session_key(
            shared_c, central_x_pub, periph_x_pub
        )
        session_key_p = BlerpcCrypto.derive_session_key(
            shared_p, central_x_pub, periph_x_pub
        )
        assert session_key_c == session_key_p

        # Step 3: Central sends confirmation
        enc_confirm_c = BlerpcCrypto.encrypt_confirmation(
            session_key_c, CONFIRM_CENTRAL
        )
        step3 = BlerpcCrypto.build_step3_payload(enc_confirm_c)
        parsed_enc = BlerpcCrypto.parse_step3_payload(step3)
        dec_confirm_c = BlerpcCrypto.decrypt_confirmation(session_key_p, parsed_enc)
        assert dec_confirm_c == CONFIRM_CENTRAL

        # Step 4: Peripheral sends confirmation
        enc_confirm_p = BlerpcCrypto.encrypt_confirmation(
            session_key_p, CONFIRM_PERIPHERAL
        )
        step4 = BlerpcCrypto.build_step4_payload(enc_confirm_p)
        parsed_enc = BlerpcCrypto.parse_step4_payload(step4)
        dec_confirm_p = BlerpcCrypto.decrypt_confirmation(session_key_c, parsed_enc)
        assert dec_confirm_p == CONFIRM_PERIPHERAL

    def test_encrypted_command_after_handshake(self):
        """After handshake, both sides can encrypt/decrypt commands."""
        key = b"\x01" * 16  # Simulated session key

        # Central sends encrypted command (C→P)
        plaintext = b"echo request data"
        encrypted = BlerpcCrypto.encrypt_command(key, 0, DIRECTION_C2P, plaintext)

        # Peripheral decrypts
        counter, decrypted = BlerpcCrypto.decrypt_command(key, DIRECTION_C2P, encrypted)
        assert counter == 0
        assert decrypted == plaintext

        # Peripheral sends encrypted response (P→C)
        resp_plaintext = b"echo response data"
        resp_encrypted = BlerpcCrypto.encrypt_command(
            key, 0, DIRECTION_P2C, resp_plaintext
        )

        # Central decrypts
        counter, resp_decrypted = BlerpcCrypto.decrypt_command(
            key, DIRECTION_P2C, resp_encrypted
        )
        assert counter == 0
        assert resp_decrypted == resp_plaintext

    def test_counter_monotonic_increase(self):
        """Counters must be strictly increasing."""
        key = b"\x01" * 16

        for i in range(5):
            encrypted = BlerpcCrypto.encrypt_command(
                key, i, DIRECTION_C2P, f"msg{i}".encode()
            )
            counter, decrypted = BlerpcCrypto.decrypt_command(
                key, DIRECTION_C2P, encrypted
            )
            assert counter == i
            assert decrypted == f"msg{i}".encode()


class TestBlerpcCryptoSession:
    def test_encrypt_decrypt_roundtrip(self):
        key = b"\x01" * 16
        central = BlerpcCryptoSession(key, is_central=True)
        peripheral = BlerpcCryptoSession(key, is_central=False)

        plaintext = b"Hello, blerpc!"
        encrypted = central.encrypt(plaintext)
        decrypted = peripheral.decrypt(encrypted)
        assert decrypted == plaintext

    def test_bidirectional(self):
        key = b"\x01" * 16
        central = BlerpcCryptoSession(key, is_central=True)
        peripheral = BlerpcCryptoSession(key, is_central=False)

        # Central -> Peripheral
        enc1 = central.encrypt(b"request")
        assert peripheral.decrypt(enc1) == b"request"

        # Peripheral -> Central
        enc2 = peripheral.encrypt(b"response")
        assert central.decrypt(enc2) == b"response"

    def test_counter_auto_increment(self):
        key = b"\x01" * 16
        central = BlerpcCryptoSession(key, is_central=True)
        peripheral = BlerpcCryptoSession(key, is_central=False)

        for i in range(5):
            enc = central.encrypt(f"msg{i}".encode())
            # Verify counter in wire format
            counter = struct.unpack_from("<I", enc, 0)[0]
            assert counter == i
            assert peripheral.decrypt(enc) == f"msg{i}".encode()

    def test_replay_detection(self):
        key = b"\x01" * 16
        central = BlerpcCryptoSession(key, is_central=True)
        peripheral = BlerpcCryptoSession(key, is_central=False)

        enc0 = central.encrypt(b"msg0")
        enc1 = central.encrypt(b"msg1")

        peripheral.decrypt(enc0)
        peripheral.decrypt(enc1)

        # Replaying enc0 should fail
        with pytest.raises(RuntimeError, match="Replay detected"):
            peripheral.decrypt(enc0)

    def test_wrong_direction_fails(self):
        key = b"\x01" * 16
        central = BlerpcCryptoSession(key, is_central=True)
        peripheral = BlerpcCryptoSession(key, is_central=False)

        enc = central.encrypt(b"test")
        # Central trying to decrypt its own message (wrong direction)
        with pytest.raises(Exception):
            central.decrypt(enc)


class TestCentralKeyExchange:
    def _make_peripheral_keys(self):
        ed_priv, ed_pub = BlerpcCrypto.generate_ed25519_keypair()
        x_priv, x_pub = BlerpcCrypto.generate_x25519_keypair()
        return x_priv, x_pub, ed_priv, ed_pub

    def test_start_produces_step1(self):
        kx = CentralKeyExchange()
        step1 = kx.start()
        assert len(step1) == 33
        assert step1[0] == KEY_EXCHANGE_STEP1

    def test_process_step2_verifies_signature(self):
        kx = CentralKeyExchange()
        step1 = kx.start()
        central_pub = BlerpcCrypto.parse_step1_payload(step1)

        x_priv, x_pub, ed_priv, ed_pub = self._make_peripheral_keys()

        sign_msg = central_pub + x_pub
        signature = BlerpcCrypto.ed25519_sign(ed_priv, sign_msg)
        step2 = BlerpcCrypto.build_step2_payload(x_pub, signature, ed_pub)

        step3 = kx.process_step2(step2)
        assert len(step3) == 45
        assert step3[0] == KEY_EXCHANGE_STEP3

    def test_process_step2_bad_signature_raises(self):
        kx = CentralKeyExchange()
        kx.start()

        _, x_pub, _, ed_pub = self._make_peripheral_keys()
        bad_sig = b"\x00" * 64
        step2 = BlerpcCrypto.build_step2_payload(x_pub, bad_sig, ed_pub)

        with pytest.raises(ValueError, match="signature verification failed"):
            kx.process_step2(step2)

    def test_verify_key_cb_reject(self):
        kx = CentralKeyExchange()
        step1 = kx.start()
        central_pub = BlerpcCrypto.parse_step1_payload(step1)

        x_priv, x_pub, ed_priv, ed_pub = self._make_peripheral_keys()
        sign_msg = central_pub + x_pub
        signature = BlerpcCrypto.ed25519_sign(ed_priv, sign_msg)
        step2 = BlerpcCrypto.build_step2_payload(x_pub, signature, ed_pub)

        with pytest.raises(ValueError, match="rejected"):
            kx.process_step2(step2, verify_key_cb=lambda _: False)

    def test_verify_key_cb_accept(self):
        kx = CentralKeyExchange()
        step1 = kx.start()
        central_pub = BlerpcCrypto.parse_step1_payload(step1)

        x_priv, x_pub, ed_priv, ed_pub = self._make_peripheral_keys()
        sign_msg = central_pub + x_pub
        signature = BlerpcCrypto.ed25519_sign(ed_priv, sign_msg)
        step2 = BlerpcCrypto.build_step2_payload(x_pub, signature, ed_pub)

        received_key = []
        step3 = kx.process_step2(
            step2, verify_key_cb=lambda k: (received_key.append(k), True)[1]
        )
        assert received_key[0] == ed_pub
        assert len(step3) == 45


class TestPeripheralKeyExchange:
    def test_process_step1_produces_step2(self):
        x_priv, _ = BlerpcCrypto.generate_x25519_keypair()
        ed_priv, _ = BlerpcCrypto.generate_ed25519_keypair()

        kx = PeripheralKeyExchange(x_priv, ed_priv)
        central_x_priv, central_x_pub = BlerpcCrypto.generate_x25519_keypair()
        step1 = BlerpcCrypto.build_step1_payload(central_x_pub)

        step2 = kx.process_step1(step1)
        assert len(step2) == 129
        assert step2[0] == KEY_EXCHANGE_STEP2

    def test_process_step3_bad_confirmation_raises(self):
        x_priv, _ = BlerpcCrypto.generate_x25519_keypair()
        ed_priv, _ = BlerpcCrypto.generate_ed25519_keypair()

        kx = PeripheralKeyExchange(x_priv, ed_priv)
        central_x_priv, central_x_pub = BlerpcCrypto.generate_x25519_keypair()
        step1 = BlerpcCrypto.build_step1_payload(central_x_pub)
        kx.process_step1(step1)

        # Build a step 3 with wrong confirmation text
        bad_encrypted = BlerpcCrypto.encrypt_confirmation(
            kx._session_key, b"WRONG_CONFIRM_XX"
        )
        bad_step3 = BlerpcCrypto.build_step3_payload(bad_encrypted)

        with pytest.raises(ValueError, match="confirmation mismatch"):
            kx.process_step3(bad_step3)


class TestKeyExchangeIntegration:
    """Full Central <-> Peripheral handshake via the new state machines."""

    def test_full_handshake_and_session(self):
        # Peripheral long-term keys
        periph_x_priv, _ = BlerpcCrypto.generate_x25519_keypair()
        periph_ed_priv, _ = BlerpcCrypto.generate_ed25519_keypair()

        central_kx = CentralKeyExchange()
        periph_kx = PeripheralKeyExchange(periph_x_priv, periph_ed_priv)

        # Step 1 -> Step 2
        step1 = central_kx.start()
        step2 = periph_kx.process_step1(step1)

        # Step 2 -> Step 3
        step3 = central_kx.process_step2(step2)

        # Step 3 -> Step 4 + peripheral session
        step4, periph_session = periph_kx.process_step3(step3)

        # Step 4 -> central session
        central_session = central_kx.finish(step4)

        # Bidirectional encrypted communication
        enc_req = central_session.encrypt(b"echo request")
        assert periph_session.decrypt(enc_req) == b"echo request"

        enc_resp = periph_session.encrypt(b"echo response")
        assert central_session.decrypt(enc_resp) == b"echo response"

    def test_handshake_with_verify_cb(self):
        periph_x_priv, _ = BlerpcCrypto.generate_x25519_keypair()
        periph_ed_priv, periph_ed_pub = BlerpcCrypto.generate_ed25519_keypair()

        central_kx = CentralKeyExchange()
        periph_kx = PeripheralKeyExchange(periph_x_priv, periph_ed_priv)

        step1 = central_kx.start()
        step2 = periph_kx.process_step1(step1)

        seen_keys = []
        step3 = central_kx.process_step2(
            step2,
            verify_key_cb=lambda k: (seen_keys.append(k), True)[1],
        )
        assert seen_keys[0] == periph_ed_pub

        step4, periph_session = periph_kx.process_step3(step3)
        central_session = central_kx.finish(step4)

        # Verify sessions work
        enc = central_session.encrypt(b"test")
        assert periph_session.decrypt(enc) == b"test"

    def test_multiple_messages_after_handshake(self):
        periph_x_priv, _ = BlerpcCrypto.generate_x25519_keypair()
        periph_ed_priv, _ = BlerpcCrypto.generate_ed25519_keypair()

        central_kx = CentralKeyExchange()
        periph_kx = PeripheralKeyExchange(periph_x_priv, periph_ed_priv)

        step1 = central_kx.start()
        step2 = periph_kx.process_step1(step1)
        step3 = central_kx.process_step2(step2)
        step4, periph_session = periph_kx.process_step3(step3)
        central_session = central_kx.finish(step4)

        # Send many messages in both directions
        for i in range(20):
            msg = f"c2p_{i}".encode()
            enc = central_session.encrypt(msg)
            assert periph_session.decrypt(enc) == msg

            resp = f"p2c_{i}".encode()
            enc_resp = periph_session.encrypt(resp)
            assert central_session.decrypt(enc_resp) == resp
