#ifndef BLERPC_PROTOCOL_CRYPTO_H
#define BLERPC_PROTOCOL_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Direction bytes for nonce construction */
#define BLERPC_DIRECTION_C2P 0x00
#define BLERPC_DIRECTION_P2C 0x01

/* Key exchange step constants */
#define BLERPC_KEY_EXCHANGE_STEP1 0x01
#define BLERPC_KEY_EXCHANGE_STEP2 0x02
#define BLERPC_KEY_EXCHANGE_STEP3 0x03
#define BLERPC_KEY_EXCHANGE_STEP4 0x04

/* Sizes */
#define BLERPC_X25519_KEY_SIZE 32
#define BLERPC_ED25519_PUBKEY_SIZE 32
#define BLERPC_ED25519_PRIVKEY_SIZE 64
#define BLERPC_ED25519_SIGNATURE_SIZE 64
#define BLERPC_SESSION_KEY_SIZE 16
#define BLERPC_AES_GCM_TAG_SIZE 16
#define BLERPC_AES_GCM_NONCE_SIZE 12
#define BLERPC_COUNTER_SIZE 4
#define BLERPC_ENCRYPTED_OVERHEAD (BLERPC_COUNTER_SIZE + BLERPC_AES_GCM_TAG_SIZE)

/* Confirmation plaintexts */
#define BLERPC_CONFIRM_CENTRAL  "BLERPC_CONFIRM_C"
#define BLERPC_CONFIRM_PERIPHERAL "BLERPC_CONFIRM_P"
#define BLERPC_CONFIRM_LEN 16

/* Step payload sizes */
#define BLERPC_STEP1_SIZE 33   /* 1 + 32 */
#define BLERPC_STEP2_SIZE 129  /* 1 + 32 + 64 + 32 */
#define BLERPC_STEP3_SIZE 45   /* 1 + 12 + 16 + 16 */
#define BLERPC_STEP4_SIZE 45   /* 1 + 12 + 16 + 16 */

/**
 * Crypto session state for encryption/decryption.
 */
struct blerpc_crypto_session {
    uint8_t session_key[BLERPC_SESSION_KEY_SIZE];
    uint32_t tx_counter;
    uint32_t rx_counter;
    uint8_t tx_direction; /* BLERPC_DIRECTION_C2P or P2C */
    uint8_t rx_direction;
    uint8_t rx_first_done;
    uint8_t active; /* 1 if session established */
};

/**
 * Generate an X25519 key pair.
 * privkey: output 32-byte private key
 * pubkey: output 32-byte public key
 * Returns 0 on success, -1 on error.
 */
int blerpc_crypto_x25519_keygen(uint8_t privkey[BLERPC_X25519_KEY_SIZE],
                                 uint8_t pubkey[BLERPC_X25519_KEY_SIZE]);

/**
 * Compute X25519 shared secret.
 * shared: output 32-byte shared secret
 * privkey: 32-byte private key
 * peer_pubkey: 32-byte peer public key
 * Returns 0 on success, -1 on error.
 */
int blerpc_crypto_x25519_shared_secret(uint8_t shared[BLERPC_X25519_KEY_SIZE],
                                        const uint8_t privkey[BLERPC_X25519_KEY_SIZE],
                                        const uint8_t peer_pubkey[BLERPC_X25519_KEY_SIZE]);

/**
 * Derive 16-byte AES-128 session key using HKDF-SHA256.
 * session_key: output 16-byte key
 * shared_secret: 32-byte X25519 shared secret
 * central_pubkey: 32-byte central X25519 public key
 * peripheral_pubkey: 32-byte peripheral X25519 public key
 * Returns 0 on success, -1 on error.
 */
int blerpc_crypto_derive_session_key(uint8_t session_key[BLERPC_SESSION_KEY_SIZE],
                                      const uint8_t shared_secret[BLERPC_X25519_KEY_SIZE],
                                      const uint8_t central_pubkey[BLERPC_X25519_KEY_SIZE],
                                      const uint8_t peripheral_pubkey[BLERPC_X25519_KEY_SIZE]);

/**
 * Sign a message with Ed25519.
 * signature: output 64-byte signature
 * privkey: 64-byte Ed25519 private key (seed + public key, as per mbedTLS)
 * msg: message to sign
 * msg_len: message length
 * Returns 0 on success, -1 on error.
 */
int blerpc_crypto_ed25519_sign(uint8_t signature[BLERPC_ED25519_SIGNATURE_SIZE],
                                const uint8_t privkey[BLERPC_ED25519_PRIVKEY_SIZE],
                                const uint8_t *msg, size_t msg_len);

/**
 * Verify an Ed25519 signature.
 * pubkey: 32-byte Ed25519 public key
 * msg: message that was signed
 * msg_len: message length
 * signature: 64-byte signature to verify
 * Returns 0 if valid, -1 if invalid or error.
 */
int blerpc_crypto_ed25519_verify(const uint8_t pubkey[BLERPC_ED25519_PUBKEY_SIZE],
                                  const uint8_t *msg, size_t msg_len,
                                  const uint8_t signature[BLERPC_ED25519_SIGNATURE_SIZE]);

/**
 * Encrypt a command payload with AES-128-GCM.
 * out: output buffer
 * out_size: output buffer capacity (must be >= plaintext_len + BLERPC_ENCRYPTED_OVERHEAD)
 * out_len: output - actual bytes written
 * session_key: 16-byte session key
 * counter: message counter
 * direction: BLERPC_DIRECTION_C2P or BLERPC_DIRECTION_P2C
 * plaintext: data to encrypt
 * plaintext_len: data length
 * Returns 0 on success, -1 on error.
 */
int blerpc_crypto_encrypt_command(uint8_t *out, size_t out_size, size_t *out_len,
                                   const uint8_t session_key[BLERPC_SESSION_KEY_SIZE],
                                   uint32_t counter, uint8_t direction,
                                   const uint8_t *plaintext, size_t plaintext_len);

/**
 * Decrypt a command payload with AES-128-GCM.
 * out: output buffer
 * out_size: output buffer capacity (must be >= data_len - BLERPC_ENCRYPTED_OVERHEAD)
 * out_len: output - actual bytes written
 * counter_out: output - the counter value from the encrypted payload
 * session_key: 16-byte session key
 * direction: BLERPC_DIRECTION_C2P or BLERPC_DIRECTION_P2C
 * data: encrypted data [counter:4B][ciphertext:NB][tag:16B]
 * data_len: total encrypted data length
 * Returns 0 on success, -1 on error (includes authentication failure).
 */
int blerpc_crypto_decrypt_command(uint8_t *out, size_t out_size, size_t *out_len,
                                   uint32_t *counter_out,
                                   const uint8_t session_key[BLERPC_SESSION_KEY_SIZE],
                                   uint8_t direction,
                                   const uint8_t *data, size_t data_len);

/**
 * Encrypt a confirmation message for key exchange step 3/4.
 * out: output buffer, must be at least 44 bytes (12 nonce + 16 ct + 16 tag)
 * session_key: 16-byte session key
 * message: 16-byte confirmation plaintext
 * Returns 0 on success, -1 on error.
 */
int blerpc_crypto_encrypt_confirmation(uint8_t out[44],
                                        const uint8_t session_key[BLERPC_SESSION_KEY_SIZE],
                                        const uint8_t message[BLERPC_CONFIRM_LEN]);

/**
 * Decrypt a confirmation message from key exchange step 3/4.
 * out: output 16-byte plaintext
 * session_key: 16-byte session key
 * data: 44-byte encrypted data (12 nonce + 16 ct + 16 tag)
 * Returns 0 on success, -1 on error.
 */
int blerpc_crypto_decrypt_confirmation(uint8_t out[BLERPC_CONFIRM_LEN],
                                        const uint8_t session_key[BLERPC_SESSION_KEY_SIZE],
                                        const uint8_t data[44]);

/**
 * Initialize a crypto session after key derivation.
 * is_central: true if this is the central side
 */
void blerpc_crypto_session_init(struct blerpc_crypto_session *s,
                                 const uint8_t session_key[BLERPC_SESSION_KEY_SIZE],
                                 int is_central);

/**
 * Encrypt using session state (auto-increments tx_counter).
 * out_size: output buffer capacity (must be >= plaintext_len + BLERPC_ENCRYPTED_OVERHEAD)
 * Returns 0 on success, -1 on error.
 */
int blerpc_crypto_session_encrypt(struct blerpc_crypto_session *s,
                                   uint8_t *out, size_t out_size, size_t *out_len,
                                   const uint8_t *plaintext, size_t plaintext_len);

/**
 * Decrypt using session state (validates and updates rx_counter).
 * out_size: output buffer capacity (must be >= data_len - BLERPC_ENCRYPTED_OVERHEAD)
 * Returns 0 on success, -1 on error (includes replay detection).
 */
int blerpc_crypto_session_decrypt(struct blerpc_crypto_session *s,
                                   uint8_t *out, size_t out_size, size_t *out_len,
                                   const uint8_t *data, size_t data_len);

/**
 * Central-side key exchange state machine.
 */
struct blerpc_central_key_exchange {
    uint8_t x25519_privkey[BLERPC_X25519_KEY_SIZE];
    uint8_t x25519_pubkey[BLERPC_X25519_KEY_SIZE];
    uint8_t session_key[BLERPC_SESSION_KEY_SIZE];
    uint8_t state; /* 0=init, 1=step1_done, 2=step2_done */
};

/**
 * Initialize central key exchange.
 * Returns 0 on success.
 */
int blerpc_central_kx_init(struct blerpc_central_key_exchange *kx);

/**
 * Generate step 1 payload (33 bytes: [0x01][pubkey:32]).
 * Must be called after init.
 * Returns 0 on success, -1 on error.
 */
int blerpc_central_kx_start(struct blerpc_central_key_exchange *kx,
                             uint8_t out[BLERPC_STEP1_SIZE]);

/**
 * Process step 2 from peripheral, verify signature, derive session key,
 * and produce step 3 payload.
 * step2: step 2 payload (129 bytes)
 * step2_len: length of step 2 payload
 * out: output step 3 payload (45 bytes)
 * periph_ed25519_pubkey_out: optional output of peripheral's Ed25519 public key (32 bytes), for TOFU
 * Returns 0 on success, -1 on error.
 */
int blerpc_central_kx_process_step2(struct blerpc_central_key_exchange *kx,
                                     const uint8_t *step2, size_t step2_len,
                                     uint8_t out[BLERPC_STEP3_SIZE],
                                     uint8_t periph_ed25519_pubkey_out[BLERPC_ED25519_PUBKEY_SIZE]);

/**
 * Process step 4 from peripheral, verify confirmation, and produce session.
 * step4: step 4 payload (45 bytes)
 * step4_len: length of step 4 payload
 * session_out: output crypto session (initialized as central)
 * Returns 0 on success, -1 on error.
 */
int blerpc_central_kx_finish(struct blerpc_central_key_exchange *kx,
                              const uint8_t *step4, size_t step4_len,
                              struct blerpc_crypto_session *session_out);

/**
 * Peripheral-side key exchange state machine.
 */
struct blerpc_peripheral_key_exchange {
    uint8_t x25519_privkey[BLERPC_X25519_KEY_SIZE];
    uint8_t x25519_pubkey[BLERPC_X25519_KEY_SIZE];
    uint8_t ed25519_privkey[BLERPC_ED25519_PRIVKEY_SIZE]; /* seed + pubkey */
    uint8_t ed25519_pubkey[BLERPC_ED25519_PUBKEY_SIZE];
    uint8_t session_key[BLERPC_SESSION_KEY_SIZE];
    uint8_t state; /* 0=init, 1=step1_done */
};

/**
 * Initialize peripheral key exchange with long-term Ed25519 key.
 * X25519 keypair is generated ephemerally per session in process_step1.
 * ed25519_privkey: 32-byte Ed25519 seed
 * Returns 0 on success, -1 on error.
 */
int blerpc_peripheral_kx_init(struct blerpc_peripheral_key_exchange *kx,
                               const uint8_t ed25519_privkey[32]);

/**
 * Process step 1 from central, sign, derive session key, produce step 2 payload.
 * step1: step 1 payload (33 bytes)
 * step1_len: length of step 1 payload
 * out: output step 2 payload (129 bytes)
 * Returns 0 on success, -1 on error.
 */
int blerpc_peripheral_kx_process_step1(struct blerpc_peripheral_key_exchange *kx,
                                        const uint8_t *step1, size_t step1_len,
                                        uint8_t out[BLERPC_STEP2_SIZE]);

/**
 * Process step 3 from central, verify confirmation, produce step 4 + session.
 * step3: step 3 payload (45 bytes)
 * step3_len: length of step 3 payload
 * out: output step 4 payload (45 bytes)
 * session_out: output crypto session (initialized as peripheral)
 * Returns 0 on success, -1 on error.
 */
int blerpc_peripheral_kx_process_step3(struct blerpc_peripheral_key_exchange *kx,
                                        const uint8_t *step3, size_t step3_len,
                                        uint8_t out[BLERPC_STEP4_SIZE],
                                        struct blerpc_crypto_session *session_out);

/**
 * Reset peripheral key exchange state (e.g., on disconnect).
 * Clears ephemeral keys and resets state to accept a new step 1.
 * The long-term Ed25519 key pair is preserved.
 */
void blerpc_peripheral_kx_reset(struct blerpc_peripheral_key_exchange *kx);

/**
 * Callback function type for sending key exchange payloads.
 * payload: data to send
 * len: data length
 * ctx: user context pointer
 * Returns 0 on success, non-zero on error.
 */
typedef int (*blerpc_kx_send_fn)(const uint8_t *payload, size_t len, void *ctx);

/**
 * Callback function type for receiving key exchange payloads.
 * buf: buffer to receive data into
 * buf_size: buffer capacity
 * out_len: output - actual bytes received
 * ctx: user context pointer
 * Returns 0 on success, non-zero on error.
 */
typedef int (*blerpc_kx_recv_fn)(uint8_t *buf, size_t buf_size, size_t *out_len, void *ctx);

/**
 * Perform the complete 4-step central key exchange using callbacks.
 * send_fn: callback to send a key exchange payload
 * recv_fn: callback to receive a key exchange payload
 * user_ctx: opaque pointer passed to callbacks
 * session_out: output crypto session (initialized as central)
 * periph_ed25519_pubkey_out: optional output of peripheral's Ed25519 public key (32 bytes)
 * Returns 0 on success, non-zero on error.
 */
int blerpc_central_perform_key_exchange(
    blerpc_kx_send_fn send_fn, blerpc_kx_recv_fn recv_fn, void *user_ctx,
    struct blerpc_crypto_session *session_out,
    uint8_t periph_ed25519_pubkey_out[BLERPC_ED25519_PUBKEY_SIZE]);

/**
 * Handle a single key exchange step on the peripheral side.
 * Dispatches based on the step byte in the payload.
 * kx: peripheral key exchange state machine
 * payload: incoming step payload
 * payload_len: payload length
 * out: output response payload buffer
 * out_size: output buffer capacity
 * out_len: output - actual response bytes written
 * session_out: output crypto session (only valid when session_established is true)
 * session_established: output - set to true when session is established (after step 3)
 * Returns 0 on success, non-zero on error.
 */
int blerpc_peripheral_kx_handle_step(
    struct blerpc_peripheral_key_exchange *kx,
    const uint8_t *payload, size_t payload_len,
    uint8_t *out, size_t out_size, size_t *out_len,
    struct blerpc_crypto_session *session_out, bool *session_established);

#ifdef __cplusplus
}
#endif

#endif /* BLERPC_PROTOCOL_CRYPTO_H */
