/**
 * Standalone C unit tests for the crypto layer.
 * Requires mbedTLS (PSA Crypto API).
 *
 * Build:
 *   gcc -o test_crypto test_crypto.c ../../c/src/crypto.c \
 *       -I../../c/include -I$(brew --prefix mbedtls)/include \
 *       -L$(brew --prefix mbedtls)/lib \
 *       -lmbedtls -lmbedcrypto -lmbedx509 -Wall -Wextra -std=c11
 *
 * Ed25519 tests require PSA_WANT_ECC_TWISTED_EDWARDS_255 to be enabled
 * in the mbedTLS build. Define HAS_EDDSA=1 at compile time to include them:
 *   -DHAS_EDDSA=1
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <psa/crypto.h>

#include "blerpc_protocol/crypto.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name)                                                                                 \
    do {                                                                                           \
        printf("  %s... ", #name);                                                                 \
        tests_run++;                                                                               \
        name();                                                                                    \
        tests_passed++;                                                                            \
        printf("PASSED\n");                                                                        \
    } while (0)

#define SKIP(name, reason)                                                                         \
    do {                                                                                           \
        printf("  %s... SKIPPED (%s)\n", #name, reason);                                           \
    } while (0)

/* Helper: check that a buffer is not all zeros */
static int is_nonzero(const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (buf[i] != 0) {
            return 1;
        }
    }
    return 0;
}

/* ===== Tests ===== */

static void test_x25519_keygen(void)
{
    uint8_t privkey[BLERPC_X25519_KEY_SIZE];
    uint8_t pubkey[BLERPC_X25519_KEY_SIZE];

    assert(blerpc_crypto_x25519_keygen(privkey, pubkey) == 0);
    assert(is_nonzero(privkey, BLERPC_X25519_KEY_SIZE));
    assert(is_nonzero(pubkey, BLERPC_X25519_KEY_SIZE));

    /* Keys should differ */
    assert(memcmp(privkey, pubkey, BLERPC_X25519_KEY_SIZE) != 0);
}

static void test_x25519_shared_secret(void)
{
    uint8_t priv_a[BLERPC_X25519_KEY_SIZE], pub_a[BLERPC_X25519_KEY_SIZE];
    uint8_t priv_b[BLERPC_X25519_KEY_SIZE], pub_b[BLERPC_X25519_KEY_SIZE];
    uint8_t shared_ab[BLERPC_X25519_KEY_SIZE], shared_ba[BLERPC_X25519_KEY_SIZE];

    assert(blerpc_crypto_x25519_keygen(priv_a, pub_a) == 0);
    assert(blerpc_crypto_x25519_keygen(priv_b, pub_b) == 0);

    assert(blerpc_crypto_x25519_shared_secret(shared_ab, priv_a, pub_b) == 0);
    assert(blerpc_crypto_x25519_shared_secret(shared_ba, priv_b, pub_a) == 0);

    /* Both sides must derive the same shared secret */
    assert(memcmp(shared_ab, shared_ba, BLERPC_X25519_KEY_SIZE) == 0);
    assert(is_nonzero(shared_ab, BLERPC_X25519_KEY_SIZE));
}

static void test_session_key_derivation(void)
{
    uint8_t priv_a[BLERPC_X25519_KEY_SIZE], pub_a[BLERPC_X25519_KEY_SIZE];
    uint8_t priv_b[BLERPC_X25519_KEY_SIZE], pub_b[BLERPC_X25519_KEY_SIZE];
    uint8_t shared[BLERPC_X25519_KEY_SIZE];
    uint8_t session_key[BLERPC_SESSION_KEY_SIZE];

    assert(blerpc_crypto_x25519_keygen(priv_a, pub_a) == 0);
    assert(blerpc_crypto_x25519_keygen(priv_b, pub_b) == 0);
    assert(blerpc_crypto_x25519_shared_secret(shared, priv_a, pub_b) == 0);
    assert(blerpc_crypto_derive_session_key(session_key, shared, pub_a, pub_b) == 0);
    assert(is_nonzero(session_key, BLERPC_SESSION_KEY_SIZE));
}

#if HAS_EDDSA
static void test_ed25519_sign_verify(void)
{
    /* Generate an Ed25519 key pair via PSA */
    uint8_t seed[32];
    assert(psa_generate_random(seed, sizeof(seed)) == PSA_SUCCESS);

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id;
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attr, PSA_ALG_PURE_EDDSA);
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS));
    psa_set_key_bits(&attr, 255);
    assert(psa_import_key(&attr, seed, 32, &key_id) == PSA_SUCCESS);

    uint8_t pubkey[BLERPC_ED25519_PUBKEY_SIZE];
    size_t pubkey_len;
    assert(psa_export_public_key(key_id, pubkey, sizeof(pubkey), &pubkey_len) == PSA_SUCCESS);
    psa_destroy_key(key_id);

    /* Build 64-byte privkey: seed(32) + pubkey(32) */
    uint8_t privkey[BLERPC_ED25519_PRIVKEY_SIZE];
    memcpy(privkey, seed, 32);
    memcpy(privkey + 32, pubkey, 32);

    const uint8_t msg[] = "hello blerpc";
    uint8_t sig[BLERPC_ED25519_SIGNATURE_SIZE];

    /* Sign should succeed */
    assert(blerpc_crypto_ed25519_sign(sig, privkey, msg, sizeof(msg) - 1) == 0);

    /* Verify should succeed */
    assert(blerpc_crypto_ed25519_verify(pubkey, msg, sizeof(msg) - 1, sig) == 0);

    /* Tamper with message — verify should fail */
    uint8_t bad_msg[] = "hello blerpc";
    bad_msg[0] = 'H';
    assert(blerpc_crypto_ed25519_verify(pubkey, bad_msg, sizeof(bad_msg) - 1, sig) != 0);
}
#endif /* HAS_EDDSA */

static void test_aes_gcm_encrypt_decrypt(void)
{
    uint8_t session_key[BLERPC_SESSION_KEY_SIZE];
    assert(psa_generate_random(session_key, sizeof(session_key)) == PSA_SUCCESS);

    const uint8_t plaintext[] = "test payload data";
    size_t pt_len = sizeof(plaintext) - 1;

    uint8_t encrypted[256];
    size_t enc_len;
    assert(blerpc_crypto_encrypt_command(encrypted, sizeof(encrypted), &enc_len,
                                         session_key, 42, BLERPC_DIRECTION_C2P,
                                         plaintext, pt_len) == 0);
    assert(enc_len == pt_len + BLERPC_ENCRYPTED_OVERHEAD);

    uint8_t decrypted[256];
    size_t dec_len;
    uint32_t counter_out;
    assert(blerpc_crypto_decrypt_command(decrypted, sizeof(decrypted), &dec_len, &counter_out,
                                         session_key, BLERPC_DIRECTION_C2P,
                                         encrypted, enc_len) == 0);
    assert(dec_len == pt_len);
    assert(counter_out == 42);
    assert(memcmp(decrypted, plaintext, pt_len) == 0);
}

static void test_confirmation_encrypt_decrypt(void)
{
    uint8_t session_key[BLERPC_SESSION_KEY_SIZE];
    assert(psa_generate_random(session_key, sizeof(session_key)) == PSA_SUCCESS);

    uint8_t encrypted[44];
    assert(blerpc_crypto_encrypt_confirmation(encrypted, session_key,
                                              (const uint8_t *)BLERPC_CONFIRM_CENTRAL) == 0);

    uint8_t decrypted[BLERPC_CONFIRM_LEN];
    assert(blerpc_crypto_decrypt_confirmation(decrypted, session_key, encrypted) == 0);
    assert(memcmp(decrypted, BLERPC_CONFIRM_CENTRAL, BLERPC_CONFIRM_LEN) == 0);
}

static void test_session_encrypt_decrypt(void)
{
    uint8_t session_key[BLERPC_SESSION_KEY_SIZE];
    assert(psa_generate_random(session_key, sizeof(session_key)) == PSA_SUCCESS);

    struct blerpc_crypto_session central, peripheral;
    blerpc_crypto_session_init(&central, session_key, 1);
    blerpc_crypto_session_init(&peripheral, session_key, 0);

    const uint8_t msg[] = "session test";
    size_t msg_len = sizeof(msg) - 1;

    /* Central encrypts, peripheral decrypts */
    uint8_t ct[256];
    size_t ct_len;
    assert(blerpc_crypto_session_encrypt(&central, ct, sizeof(ct), &ct_len, msg, msg_len) == 0);

    uint8_t pt[256];
    size_t pt_len;
    assert(blerpc_crypto_session_decrypt(&peripheral, pt, sizeof(pt), &pt_len, ct, ct_len) == 0);
    assert(pt_len == msg_len);
    assert(memcmp(pt, msg, msg_len) == 0);

    /* Peripheral encrypts, central decrypts */
    const uint8_t msg2[] = "response data";
    size_t msg2_len = sizeof(msg2) - 1;
    assert(blerpc_crypto_session_encrypt(&peripheral, ct, sizeof(ct), &ct_len, msg2, msg2_len) == 0);
    assert(blerpc_crypto_session_decrypt(&central, pt, sizeof(pt), &pt_len, ct, ct_len) == 0);
    assert(pt_len == msg2_len);
    assert(memcmp(pt, msg2, msg2_len) == 0);
}

static void test_replay_detection(void)
{
    uint8_t session_key[BLERPC_SESSION_KEY_SIZE];
    assert(psa_generate_random(session_key, sizeof(session_key)) == PSA_SUCCESS);

    struct blerpc_crypto_session central, peripheral;
    blerpc_crypto_session_init(&central, session_key, 1);
    blerpc_crypto_session_init(&peripheral, session_key, 0);

    const uint8_t msg[] = "replay test";
    size_t msg_len = sizeof(msg) - 1;

    uint8_t ct[256];
    size_t ct_len;
    assert(blerpc_crypto_session_encrypt(&central, ct, sizeof(ct), &ct_len, msg, msg_len) == 0);

    /* First decrypt succeeds */
    uint8_t pt[256];
    size_t pt_len;
    assert(blerpc_crypto_session_decrypt(&peripheral, pt, sizeof(pt), &pt_len, ct, ct_len) == 0);

    /* Second decrypt with same ciphertext should fail (replay) */
    assert(blerpc_crypto_session_decrypt(&peripheral, pt, sizeof(pt), &pt_len, ct, ct_len) != 0);
}

#if HAS_EDDSA
static void test_central_key_exchange_full_flow(void)
{
    struct blerpc_central_key_exchange central_kx;
    struct blerpc_peripheral_key_exchange periph_kx;

    /* Generate peripheral long-term Ed25519 key (X25519 is now ephemeral) */
    uint8_t ed25519_seed[32];
    assert(psa_generate_random(ed25519_seed, sizeof(ed25519_seed)) == PSA_SUCCESS);

    assert(blerpc_central_kx_init(&central_kx) == 0);
    assert(blerpc_peripheral_kx_init(&periph_kx, ed25519_seed) == 0);

    /* Step 1: Central -> Peripheral */
    uint8_t step1[BLERPC_STEP1_SIZE];
    assert(blerpc_central_kx_start(&central_kx, step1) == 0);

    /* Step 2: Peripheral -> Central (ephemeral X25519 generated here) */
    uint8_t step2[BLERPC_STEP2_SIZE];
    assert(blerpc_peripheral_kx_process_step1(&periph_kx, step1, BLERPC_STEP1_SIZE, step2) == 0);

    /* Step 3: Central -> Peripheral */
    uint8_t step3[BLERPC_STEP3_SIZE];
    uint8_t periph_ed25519_pub[BLERPC_ED25519_PUBKEY_SIZE];
    assert(blerpc_central_kx_process_step2(&central_kx, step2, BLERPC_STEP2_SIZE, step3,
                                           periph_ed25519_pub) == 0);

    /* Step 4: Peripheral -> Central */
    uint8_t step4[BLERPC_STEP4_SIZE];
    struct blerpc_crypto_session periph_session;
    assert(blerpc_peripheral_kx_process_step3(&periph_kx, step3, BLERPC_STEP3_SIZE, step4,
                                              &periph_session) == 0);

    /* Finish: Central gets session */
    struct blerpc_crypto_session central_session;
    assert(blerpc_central_kx_finish(&central_kx, step4, BLERPC_STEP4_SIZE, &central_session) == 0);

    /* Both sessions should work for encryption/decryption */
    const uint8_t msg[] = "key exchange test";
    size_t msg_len = sizeof(msg) - 1;
    uint8_t ct[256], pt[256];
    size_t ct_len, pt_len;

    assert(blerpc_crypto_session_encrypt(&central_session, ct, sizeof(ct), &ct_len, msg, msg_len) == 0);
    assert(blerpc_crypto_session_decrypt(&periph_session, pt, sizeof(pt), &pt_len, ct, ct_len) == 0);
    assert(pt_len == msg_len);
    assert(memcmp(pt, msg, msg_len) == 0);
}

static void test_peripheral_handle_step(void)
{
    struct blerpc_central_key_exchange central_kx;
    struct blerpc_peripheral_key_exchange periph_kx;

    uint8_t ed25519_seed[32];
    assert(psa_generate_random(ed25519_seed, sizeof(ed25519_seed)) == PSA_SUCCESS);

    assert(blerpc_central_kx_init(&central_kx) == 0);
    assert(blerpc_peripheral_kx_init(&periph_kx, ed25519_seed) == 0);

    /* Step 1 via handle_step */
    uint8_t step1[BLERPC_STEP1_SIZE];
    assert(blerpc_central_kx_start(&central_kx, step1) == 0);

    uint8_t out[256];
    size_t out_len;
    struct blerpc_crypto_session session;
    bool established;

    assert(blerpc_peripheral_kx_handle_step(&periph_kx, step1, BLERPC_STEP1_SIZE, out, sizeof(out),
                                            &out_len, &session, &established) == 0);
    assert(!established);
    assert(out_len == BLERPC_STEP2_SIZE);

    /* Process step 2 on central side */
    uint8_t step3[BLERPC_STEP3_SIZE];
    assert(blerpc_central_kx_process_step2(&central_kx, out, out_len, step3, NULL) == 0);

    /* Step 3 via handle_step */
    assert(blerpc_peripheral_kx_handle_step(&periph_kx, step3, BLERPC_STEP3_SIZE, out, sizeof(out),
                                            &out_len, &session, &established) == 0);
    assert(established);
    assert(out_len == BLERPC_STEP4_SIZE);
    assert(session.active == 1);
}
#endif /* HAS_EDDSA */

int main(void)
{
    assert(psa_crypto_init() == PSA_SUCCESS);

    printf("Running crypto tests...\n");

    TEST(test_x25519_keygen);
    TEST(test_x25519_shared_secret);
    TEST(test_session_key_derivation);
#if HAS_EDDSA
    TEST(test_ed25519_sign_verify);
#else
    SKIP(test_ed25519_sign_verify, "Ed25519 not available");
#endif
    TEST(test_aes_gcm_encrypt_decrypt);
    TEST(test_confirmation_encrypt_decrypt);
    TEST(test_session_encrypt_decrypt);
    TEST(test_replay_detection);
#if HAS_EDDSA
    TEST(test_central_key_exchange_full_flow);
    TEST(test_peripheral_handle_step);
#else
    SKIP(test_central_key_exchange_full_flow, "Ed25519 not available");
    SKIP(test_peripheral_handle_step, "Ed25519 not available");
#endif

    printf("\n%d/%d tests passed.\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
