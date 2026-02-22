#include "blerpc_protocol/crypto.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <mbedtls/platform_util.h>
#include <psa/crypto.h>

/* Build 12-byte nonce: counter(4B LE) || direction(1B) || zeros(7B) */
static void build_nonce(uint8_t nonce[BLERPC_AES_GCM_NONCE_SIZE],
                        uint32_t counter, uint8_t direction)
{
    memset(nonce, 0, BLERPC_AES_GCM_NONCE_SIZE);
    nonce[0] = (uint8_t)(counter & 0xFF);
    nonce[1] = (uint8_t)((counter >> 8) & 0xFF);
    nonce[2] = (uint8_t)((counter >> 16) & 0xFF);
    nonce[3] = (uint8_t)((counter >> 24) & 0xFF);
    nonce[4] = direction;
}

int blerpc_crypto_x25519_keygen(uint8_t privkey[BLERPC_X25519_KEY_SIZE],
                                 uint8_t pubkey[BLERPC_X25519_KEY_SIZE])
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id;
    psa_status_t status;
    size_t pubkey_len;

    status = psa_generate_random(privkey, BLERPC_X25519_KEY_SIZE);
    if (status != PSA_SUCCESS) {
        return -1;
    }

    /* RFC 7748 clamping: work around CRACEN driver not clamping during
     * psa_export_public_key (public key generation path), while it does
     * clamp during psa_raw_key_agreement (ECDH path).  Pre-clamping
     * ensures both paths use the same effective scalar. */
    privkey[0] &= 0xF8;   /* clear bits 0, 1, 2 */
    privkey[31] &= 0x7F;  /* clear bit 255 */
    privkey[31] |= 0x40;  /* set bit 254 */

    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
    psa_set_key_bits(&attr, 255);

    status = psa_import_key(&attr, privkey, BLERPC_X25519_KEY_SIZE, &key_id);
    if (status != PSA_SUCCESS) {
        return -1;
    }

    status = psa_export_public_key(key_id, pubkey, BLERPC_X25519_KEY_SIZE, &pubkey_len);
    psa_destroy_key(key_id);
    if (status != PSA_SUCCESS) {
        return -1;
    }

    return 0;
}

int blerpc_crypto_x25519_shared_secret(uint8_t shared[BLERPC_X25519_KEY_SIZE],
                                        const uint8_t privkey[BLERPC_X25519_KEY_SIZE],
                                        const uint8_t peer_pubkey[BLERPC_X25519_KEY_SIZE])
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id;
    psa_status_t status;
    size_t shared_len;

    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDH);
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
    psa_set_key_bits(&attr, 255);

    status = psa_import_key(&attr, privkey, BLERPC_X25519_KEY_SIZE, &key_id);
    if (status != PSA_SUCCESS) {
        return -1;
    }

    status = psa_raw_key_agreement(PSA_ALG_ECDH, key_id,
                                    peer_pubkey, BLERPC_X25519_KEY_SIZE,
                                    shared, BLERPC_X25519_KEY_SIZE, &shared_len);
    psa_destroy_key(key_id);
    if (status != PSA_SUCCESS) {
        return -1;
    }

    return 0;
}

int blerpc_crypto_derive_session_key(uint8_t session_key[BLERPC_SESSION_KEY_SIZE],
                                      const uint8_t shared_secret[BLERPC_X25519_KEY_SIZE],
                                      const uint8_t central_pubkey[BLERPC_X25519_KEY_SIZE],
                                      const uint8_t peripheral_pubkey[BLERPC_X25519_KEY_SIZE])
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id;
    psa_status_t status;
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;

    /* Import shared_secret as key derivation input key */
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attr, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    psa_set_key_type(&attr, PSA_KEY_TYPE_DERIVE);
    psa_set_key_bits(&attr, 256);

    status = psa_import_key(&attr, shared_secret, BLERPC_X25519_KEY_SIZE, &key_id);
    if (status != PSA_SUCCESS) {
        return -1;
    }

    /* Build salt: central_pubkey || peripheral_pubkey (64 bytes) */
    uint8_t salt[64];
    memcpy(salt, central_pubkey, BLERPC_X25519_KEY_SIZE);
    memcpy(salt + BLERPC_X25519_KEY_SIZE, peripheral_pubkey, BLERPC_X25519_KEY_SIZE);

    status = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT,
                                             salt, sizeof(salt));
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    status = psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET, key_id);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    static const uint8_t info[] = "blerpc-session-key";
    status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO,
                                             info, sizeof(info) - 1);
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    status = psa_key_derivation_output_bytes(&op, session_key, BLERPC_SESSION_KEY_SIZE);

cleanup:
    psa_key_derivation_abort(&op);
    psa_destroy_key(key_id);
    return (status == PSA_SUCCESS) ? 0 : -1;
}

int blerpc_crypto_ed25519_sign(uint8_t signature[BLERPC_ED25519_SIGNATURE_SIZE],
                                const uint8_t privkey[BLERPC_ED25519_PRIVKEY_SIZE],
                                const uint8_t *msg, size_t msg_len)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id;
    psa_status_t status;
    size_t sig_len;

    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attr, PSA_ALG_PURE_EDDSA);
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS));
    psa_set_key_bits(&attr, 255);

    status = psa_import_key(&attr, privkey, BLERPC_ED25519_PRIVKEY_SIZE, &key_id);
    if (status != PSA_SUCCESS) {
        /* Try with just seed (32 bytes) */
        status = psa_import_key(&attr, privkey, 32, &key_id);
        if (status != PSA_SUCCESS) {
            return -1;
        }
    }

    status = psa_sign_message(key_id, PSA_ALG_PURE_EDDSA,
                               msg, msg_len,
                               signature, BLERPC_ED25519_SIGNATURE_SIZE, &sig_len);
    psa_destroy_key(key_id);
    return (status == PSA_SUCCESS) ? 0 : -1;
}

int blerpc_crypto_ed25519_verify(const uint8_t pubkey[BLERPC_ED25519_PUBKEY_SIZE],
                                  const uint8_t *msg, size_t msg_len,
                                  const uint8_t signature[BLERPC_ED25519_SIGNATURE_SIZE])
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id;
    psa_status_t status;

    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attr, PSA_ALG_PURE_EDDSA);
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS));
    psa_set_key_bits(&attr, 255);

    status = psa_import_key(&attr, pubkey, BLERPC_ED25519_PUBKEY_SIZE, &key_id);
    if (status != PSA_SUCCESS) {
        return -1;
    }

    status = psa_verify_message(key_id, PSA_ALG_PURE_EDDSA,
                                 msg, msg_len,
                                 signature, BLERPC_ED25519_SIGNATURE_SIZE);
    psa_destroy_key(key_id);
    return (status == PSA_SUCCESS) ? 0 : -1;
}

int blerpc_crypto_encrypt_command(uint8_t *out, size_t out_size, size_t *out_len,
                                   const uint8_t session_key[BLERPC_SESSION_KEY_SIZE],
                                   uint32_t counter, uint8_t direction,
                                   const uint8_t *plaintext, size_t plaintext_len)
{
    size_t required = plaintext_len + BLERPC_ENCRYPTED_OVERHEAD;
    if (out_size < required) {
        return -1;
    }

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id;
    psa_status_t status;
    uint8_t nonce[BLERPC_AES_GCM_NONCE_SIZE];
    size_t ct_len;

    build_nonce(nonce, counter, direction);

    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_GCM);
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 128);

    status = psa_import_key(&attr, session_key, BLERPC_SESSION_KEY_SIZE, &key_id);
    if (status != PSA_SUCCESS) {
        return -1;
    }

    /* Write counter first (4 bytes LE) */
    out[0] = (uint8_t)(counter & 0xFF);
    out[1] = (uint8_t)((counter >> 8) & 0xFF);
    out[2] = (uint8_t)((counter >> 16) & 0xFF);
    out[3] = (uint8_t)((counter >> 24) & 0xFF);

    status = psa_aead_encrypt(key_id, PSA_ALG_GCM,
                               nonce, BLERPC_AES_GCM_NONCE_SIZE,
                               NULL, 0,
                               plaintext, plaintext_len,
                               out + BLERPC_COUNTER_SIZE,
                               out_size - BLERPC_COUNTER_SIZE,
                               &ct_len);
    psa_destroy_key(key_id);
    if (status != PSA_SUCCESS) {
        return -1;
    }

    *out_len = BLERPC_COUNTER_SIZE + ct_len;
    return 0;
}

int blerpc_crypto_decrypt_command(uint8_t *out, size_t out_size, size_t *out_len,
                                   uint32_t *counter_out,
                                   const uint8_t session_key[BLERPC_SESSION_KEY_SIZE],
                                   uint8_t direction,
                                   const uint8_t *data, size_t data_len)
{
    if (data_len < BLERPC_ENCRYPTED_OVERHEAD) {
        return -1;
    }

    size_t plaintext_len = data_len - BLERPC_ENCRYPTED_OVERHEAD;
    if (out_size < plaintext_len) {
        return -1;
    }

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id;
    psa_status_t status;
    uint8_t nonce[BLERPC_AES_GCM_NONCE_SIZE];

    /* Extract counter */
    uint32_t counter = (uint32_t)data[0] |
                       ((uint32_t)data[1] << 8) |
                       ((uint32_t)data[2] << 16) |
                       ((uint32_t)data[3] << 24);

    build_nonce(nonce, counter, direction);

    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_GCM);
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 128);

    status = psa_import_key(&attr, session_key, BLERPC_SESSION_KEY_SIZE, &key_id);
    if (status != PSA_SUCCESS) {
        return -1;
    }

    size_t ct_and_tag_len = data_len - BLERPC_COUNTER_SIZE;
    status = psa_aead_decrypt(key_id, PSA_ALG_GCM,
                               nonce, BLERPC_AES_GCM_NONCE_SIZE,
                               NULL, 0,
                               data + BLERPC_COUNTER_SIZE, ct_and_tag_len,
                               out, out_size,
                               out_len);
    psa_destroy_key(key_id);
    if (status != PSA_SUCCESS) {
        return -1;
    }

    if (counter_out) {
        *counter_out = counter;
    }
    return 0;
}

int blerpc_crypto_encrypt_confirmation(uint8_t out[44],
                                        const uint8_t session_key[BLERPC_SESSION_KEY_SIZE],
                                        const uint8_t message[BLERPC_CONFIRM_LEN])
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id;
    psa_status_t status;
    size_t ct_len;

    /* Generate random nonce */
    status = psa_generate_random(out, BLERPC_AES_GCM_NONCE_SIZE);
    if (status != PSA_SUCCESS) {
        return -1;
    }

    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_GCM);
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 128);

    status = psa_import_key(&attr, session_key, BLERPC_SESSION_KEY_SIZE, &key_id);
    if (status != PSA_SUCCESS) {
        return -1;
    }

    status = psa_aead_encrypt(key_id, PSA_ALG_GCM,
                               out, BLERPC_AES_GCM_NONCE_SIZE,
                               NULL, 0,
                               message, BLERPC_CONFIRM_LEN,
                               out + BLERPC_AES_GCM_NONCE_SIZE,
                               BLERPC_CONFIRM_LEN + BLERPC_AES_GCM_TAG_SIZE,
                               &ct_len);
    psa_destroy_key(key_id);
    return (status == PSA_SUCCESS) ? 0 : -1;
}

int blerpc_crypto_decrypt_confirmation(uint8_t out[BLERPC_CONFIRM_LEN],
                                        const uint8_t session_key[BLERPC_SESSION_KEY_SIZE],
                                        const uint8_t data[44])
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id;
    psa_status_t status;
    size_t pt_len;

    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_GCM);
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 128);

    status = psa_import_key(&attr, session_key, BLERPC_SESSION_KEY_SIZE, &key_id);
    if (status != PSA_SUCCESS) {
        return -1;
    }

    status = psa_aead_decrypt(key_id, PSA_ALG_GCM,
                               data, BLERPC_AES_GCM_NONCE_SIZE,
                               NULL, 0,
                               data + BLERPC_AES_GCM_NONCE_SIZE,
                               BLERPC_CONFIRM_LEN + BLERPC_AES_GCM_TAG_SIZE,
                               out, BLERPC_CONFIRM_LEN,
                               &pt_len);
    psa_destroy_key(key_id);
    return (status == PSA_SUCCESS) ? 0 : -1;
}

void blerpc_crypto_session_init(struct blerpc_crypto_session *s,
                                 const uint8_t session_key[BLERPC_SESSION_KEY_SIZE],
                                 int is_central)
{
    memcpy(s->session_key, session_key, BLERPC_SESSION_KEY_SIZE);
    s->tx_counter = 0;
    s->rx_counter = 0;
    s->tx_direction = is_central ? BLERPC_DIRECTION_C2P : BLERPC_DIRECTION_P2C;
    s->rx_direction = is_central ? BLERPC_DIRECTION_P2C : BLERPC_DIRECTION_C2P;
    s->rx_first_done = 0;
    s->active = 1;
}

int blerpc_crypto_session_encrypt(struct blerpc_crypto_session *s,
                                   uint8_t *out, size_t out_size, size_t *out_len,
                                   const uint8_t *plaintext, size_t plaintext_len)
{
    if (!s->active) {
        return -1;
    }

    if (s->tx_counter == UINT32_MAX) {
        return -1;
    }

    int rc = blerpc_crypto_encrypt_command(out, out_size, out_len,
                                            s->session_key, s->tx_counter,
                                            s->tx_direction,
                                            plaintext, plaintext_len);
    if (rc == 0) {
        s->tx_counter++;
    }
    return rc;
}

int blerpc_crypto_session_decrypt(struct blerpc_crypto_session *s,
                                   uint8_t *out, size_t out_size, size_t *out_len,
                                   const uint8_t *data, size_t data_len)
{
    if (!s->active) {
        return -1;
    }

    uint32_t counter;
    int rc = blerpc_crypto_decrypt_command(out, out_size, out_len, &counter,
                                            s->session_key, s->rx_direction,
                                            data, data_len);
    if (rc != 0) {
        return -1;
    }

    /* Replay protection: counter must be strictly greater than last seen */
    if (s->rx_first_done && counter <= s->rx_counter) {
        return -1;
    }
    s->rx_counter = counter;
    s->rx_first_done = 1;
    return 0;
}

/* ── Central key exchange state machine ──────────────────────────────── */

int blerpc_central_kx_init(struct blerpc_central_key_exchange *kx)
{
    mbedtls_platform_zeroize(kx, sizeof(*kx));
    return 0;
}

int blerpc_central_kx_start(struct blerpc_central_key_exchange *kx,
                             uint8_t out[BLERPC_STEP1_SIZE])
{
    if (blerpc_crypto_x25519_keygen(kx->x25519_privkey, kx->x25519_pubkey) != 0) {
        return -1;
    }

    out[0] = BLERPC_KEY_EXCHANGE_STEP1;
    memcpy(out + 1, kx->x25519_pubkey, BLERPC_X25519_KEY_SIZE);
    kx->state = 1;
    return 0;
}

int blerpc_central_kx_process_step2(struct blerpc_central_key_exchange *kx,
                                     const uint8_t *step2, size_t step2_len,
                                     uint8_t out[BLERPC_STEP3_SIZE],
                                     uint8_t periph_ed25519_pubkey_out[BLERPC_ED25519_PUBKEY_SIZE])
{
    if (kx->state != 1) {
        return -1;
    }
    if (step2_len < BLERPC_STEP2_SIZE || step2[0] != BLERPC_KEY_EXCHANGE_STEP2) {
        return -1;
    }

    const uint8_t *periph_x25519_pub = step2 + 1;
    const uint8_t *signature = step2 + 1 + BLERPC_X25519_KEY_SIZE;
    const uint8_t *periph_ed25519_pub = step2 + 1 + BLERPC_X25519_KEY_SIZE +
                                        BLERPC_ED25519_SIGNATURE_SIZE;

    /* Verify Ed25519 signature over central_pubkey || peripheral_pubkey */
    uint8_t sign_msg[BLERPC_X25519_KEY_SIZE * 2];
    memcpy(sign_msg, kx->x25519_pubkey, BLERPC_X25519_KEY_SIZE);
    memcpy(sign_msg + BLERPC_X25519_KEY_SIZE, periph_x25519_pub, BLERPC_X25519_KEY_SIZE);

    if (blerpc_crypto_ed25519_verify(periph_ed25519_pub, sign_msg,
                                       sizeof(sign_msg), signature) != 0) {
        return -1;
    }

    /* Output peripheral's Ed25519 public key for TOFU */
    if (periph_ed25519_pubkey_out) {
        memcpy(periph_ed25519_pubkey_out, periph_ed25519_pub, BLERPC_ED25519_PUBKEY_SIZE);
    }

    /* Derive shared secret and session key */
    uint8_t shared_secret[BLERPC_X25519_KEY_SIZE];
    if (blerpc_crypto_x25519_shared_secret(shared_secret, kx->x25519_privkey,
                                            periph_x25519_pub) != 0) {
        return -1;
    }

    if (blerpc_crypto_derive_session_key(kx->session_key, shared_secret,
                                          kx->x25519_pubkey, periph_x25519_pub) != 0) {
        mbedtls_platform_zeroize(shared_secret, sizeof(shared_secret));
        return -1;
    }
    mbedtls_platform_zeroize(shared_secret, sizeof(shared_secret));

    /* Build step 3: [0x03][encrypted_confirmation:44] */
    uint8_t confirmation[44];
    if (blerpc_crypto_encrypt_confirmation(confirmation, kx->session_key,
                                            (const uint8_t *)BLERPC_CONFIRM_CENTRAL) != 0) {
        return -1;
    }

    out[0] = BLERPC_KEY_EXCHANGE_STEP3;
    memcpy(out + 1, confirmation, 44);
    kx->state = 2;
    return 0;
}

int blerpc_central_kx_finish(struct blerpc_central_key_exchange *kx,
                              const uint8_t *step4, size_t step4_len,
                              struct blerpc_crypto_session *session_out)
{
    if (kx->state != 2) {
        return -1;
    }
    if (step4_len < BLERPC_STEP4_SIZE || step4[0] != BLERPC_KEY_EXCHANGE_STEP4) {
        return -1;
    }

    /* Decrypt and verify peripheral's confirmation */
    uint8_t plaintext[BLERPC_CONFIRM_LEN];
    if (blerpc_crypto_decrypt_confirmation(plaintext, kx->session_key, step4 + 1) != 0) {
        return -1;
    }

    if (memcmp(plaintext, BLERPC_CONFIRM_PERIPHERAL, BLERPC_CONFIRM_LEN) != 0) {
        return -1;
    }

    blerpc_crypto_session_init(session_out, kx->session_key, 1);
    return 0;
}

/* ── Peripheral key exchange state machine ───────────────────────────── */

int blerpc_peripheral_kx_init(struct blerpc_peripheral_key_exchange *kx,
                               const uint8_t ed25519_privkey[32])
{
    mbedtls_platform_zeroize(kx, sizeof(*kx));

    /* Derive Ed25519 public key from seed, store full key (seed + pubkey) */
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id;
    size_t pubkey_len;

    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attr, PSA_ALG_PURE_EDDSA);
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS));
    psa_set_key_bits(&attr, 255);

    if (psa_import_key(&attr, ed25519_privkey, 32, &key_id) != PSA_SUCCESS) {
        return -1;
    }
    psa_status_t status = psa_export_public_key(key_id, kx->ed25519_pubkey,
                                    BLERPC_ED25519_PUBKEY_SIZE, &pubkey_len);
    psa_destroy_key(key_id);
    if (status != PSA_SUCCESS) {
        return -1;
    }

    /* Build full Ed25519 private key: seed (32) + pubkey (32) */
    memcpy(kx->ed25519_privkey, ed25519_privkey, 32);
    memcpy(kx->ed25519_privkey + 32, kx->ed25519_pubkey, 32);

    return 0;
}

int blerpc_peripheral_kx_process_step1(struct blerpc_peripheral_key_exchange *kx,
                                        const uint8_t *step1, size_t step1_len,
                                        uint8_t out[BLERPC_STEP2_SIZE])
{
    if (step1_len < BLERPC_STEP1_SIZE || step1[0] != BLERPC_KEY_EXCHANGE_STEP1) {
        return -1;
    }

    /* Generate ephemeral X25519 keypair for this session (forward secrecy) */
    if (blerpc_crypto_x25519_keygen(kx->x25519_privkey, kx->x25519_pubkey) != 0) {
        return -1;
    }

    const uint8_t *central_x25519_pub = step1 + 1;

    /* Sign: central_pubkey || peripheral_pubkey */
    uint8_t sign_msg[BLERPC_X25519_KEY_SIZE * 2];
    memcpy(sign_msg, central_x25519_pub, BLERPC_X25519_KEY_SIZE);
    memcpy(sign_msg + BLERPC_X25519_KEY_SIZE, kx->x25519_pubkey, BLERPC_X25519_KEY_SIZE);

    uint8_t signature[BLERPC_ED25519_SIGNATURE_SIZE];
    if (blerpc_crypto_ed25519_sign(signature, kx->ed25519_privkey,
                                    sign_msg, sizeof(sign_msg)) != 0) {
        return -1;
    }

    /* Derive shared secret and session key */
    uint8_t shared_secret[BLERPC_X25519_KEY_SIZE];
    if (blerpc_crypto_x25519_shared_secret(shared_secret, kx->x25519_privkey,
                                            central_x25519_pub) != 0) {
        return -1;
    }

    if (blerpc_crypto_derive_session_key(kx->session_key, shared_secret,
                                          central_x25519_pub, kx->x25519_pubkey) != 0) {
        mbedtls_platform_zeroize(shared_secret, sizeof(shared_secret));
        return -1;
    }
    mbedtls_platform_zeroize(shared_secret, sizeof(shared_secret));

    /* Build step 2: [0x02][periph_x25519_pub:32][sig:64][periph_ed25519_pub:32] */
    out[0] = BLERPC_KEY_EXCHANGE_STEP2;
    memcpy(out + 1, kx->x25519_pubkey, BLERPC_X25519_KEY_SIZE);
    memcpy(out + 1 + BLERPC_X25519_KEY_SIZE, signature, BLERPC_ED25519_SIGNATURE_SIZE);
    memcpy(out + 1 + BLERPC_X25519_KEY_SIZE + BLERPC_ED25519_SIGNATURE_SIZE,
           kx->ed25519_pubkey, BLERPC_ED25519_PUBKEY_SIZE);

    kx->state = 1;
    return 0;
}

int blerpc_peripheral_kx_process_step3(struct blerpc_peripheral_key_exchange *kx,
                                        const uint8_t *step3, size_t step3_len,
                                        uint8_t out[BLERPC_STEP4_SIZE],
                                        struct blerpc_crypto_session *session_out)
{
    if (step3_len < BLERPC_STEP3_SIZE || step3[0] != BLERPC_KEY_EXCHANGE_STEP3) {
        return -1;
    }

    /* Decrypt and verify central's confirmation */
    uint8_t plaintext[BLERPC_CONFIRM_LEN];
    if (blerpc_crypto_decrypt_confirmation(plaintext, kx->session_key, step3 + 1) != 0) {
        return -1;
    }

    if (memcmp(plaintext, BLERPC_CONFIRM_CENTRAL, BLERPC_CONFIRM_LEN) != 0) {
        return -1;
    }

    /* Build step 4: [0x04][encrypted_confirmation:44] */
    uint8_t confirmation[44];
    if (blerpc_crypto_encrypt_confirmation(confirmation, kx->session_key,
                                            (const uint8_t *)BLERPC_CONFIRM_PERIPHERAL) != 0) {
        return -1;
    }

    out[0] = BLERPC_KEY_EXCHANGE_STEP4;
    memcpy(out + 1, confirmation, 44);

    blerpc_crypto_session_init(session_out, kx->session_key, 0);
    return 0;
}

void blerpc_peripheral_kx_reset(struct blerpc_peripheral_key_exchange *kx)
{
    kx->state = 0;
    mbedtls_platform_zeroize(kx->x25519_privkey, sizeof(kx->x25519_privkey));
    mbedtls_platform_zeroize(kx->x25519_pubkey, sizeof(kx->x25519_pubkey));
    mbedtls_platform_zeroize(kx->session_key, sizeof(kx->session_key));
}

/* ── High-level key exchange helpers ─────────────────────────────────── */

int blerpc_central_perform_key_exchange(
    blerpc_kx_send_fn send_fn, blerpc_kx_recv_fn recv_fn, void *user_ctx,
    struct blerpc_crypto_session *session_out,
    uint8_t periph_ed25519_pubkey_out[BLERPC_ED25519_PUBKEY_SIZE])
{
    struct blerpc_central_key_exchange kx;
    int rc;

    blerpc_central_kx_init(&kx);

    /* Step 1: Generate ephemeral keypair and send */
    uint8_t step1[BLERPC_STEP1_SIZE];
    rc = blerpc_central_kx_start(&kx, step1);
    if (rc != 0) {
        return rc;
    }
    rc = send_fn(step1, BLERPC_STEP1_SIZE, user_ctx);
    if (rc != 0) {
        return rc;
    }

    /* Step 2: Receive peripheral's response */
    uint8_t step2[BLERPC_STEP2_SIZE];
    size_t step2_len;
    rc = recv_fn(step2, sizeof(step2), &step2_len, user_ctx);
    if (rc != 0) {
        return rc;
    }

    /* Process step 2 and produce step 3 */
    uint8_t step3[BLERPC_STEP3_SIZE];
    rc = blerpc_central_kx_process_step2(&kx, step2, step2_len, step3,
                                          periph_ed25519_pubkey_out);
    if (rc != 0) {
        return rc;
    }

    /* Send step 3 */
    rc = send_fn(step3, BLERPC_STEP3_SIZE, user_ctx);
    if (rc != 0) {
        return rc;
    }

    /* Step 4: Receive peripheral's confirmation */
    uint8_t step4[BLERPC_STEP4_SIZE];
    size_t step4_len;
    rc = recv_fn(step4, sizeof(step4), &step4_len, user_ctx);
    if (rc != 0) {
        return rc;
    }

    /* Finish: verify confirmation and produce session */
    return blerpc_central_kx_finish(&kx, step4, step4_len, session_out);
}

int blerpc_peripheral_kx_handle_step(
    struct blerpc_peripheral_key_exchange *kx,
    const uint8_t *payload, size_t payload_len,
    uint8_t *out, size_t out_size, size_t *out_len,
    struct blerpc_crypto_session *session_out, bool *session_established)
{
    if (payload_len < 1) {
        return -1;
    }

    *session_established = false;

    uint8_t step = payload[0];

    if (step == BLERPC_KEY_EXCHANGE_STEP1) {
        if (kx->state != 0) {
            return -1;
        }
        if (out_size < BLERPC_STEP2_SIZE) {
            return -1;
        }
        int rc = blerpc_peripheral_kx_process_step1(kx, payload, payload_len, out);
        if (rc != 0) {
            return rc;
        }
        *out_len = BLERPC_STEP2_SIZE;
        return 0;

    } else if (step == BLERPC_KEY_EXCHANGE_STEP3) {
        if (kx->state != 1) {
            return -1;
        }
        if (out_size < BLERPC_STEP4_SIZE) {
            return -1;
        }
        int rc = blerpc_peripheral_kx_process_step3(kx, payload, payload_len,
                                                     out, session_out);
        if (rc != 0) {
            return rc;
        }
        *out_len = BLERPC_STEP4_SIZE;
        *session_established = true;
        return 0;
    }

    return -1;
}
