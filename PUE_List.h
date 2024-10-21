#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <time.h>

#include <openssl/rand.h>

#define KEY_LEN 16
#define IV_LEN 16
#define TAG_LEN 16
#define SEED_LEN 16
#define HASH_LEN 32
#define P 50
#define HEADER_CONTENT_LEN (HASH_LEN + KEY_LEN + SEED_LEN * P)
#define HEADER_LEN (SEED_LEN + IV_LEN + TAG_LEN + HEADER_CONTENT_LEN)
#define CTXT_OVERHEAD (HEADER_LEN + IV_LEN) 

typedef struct AE_key AE_key;
typedef struct AE_ctx_header AE_ctx_header;
typedef struct ct_hat_data ct_hat_data;
typedef struct ct_hat_data_en ct_hat_data_en;
typedef struct AE_ctx_len AE_ctx_len;
typedef struct delta_token_data delta_token_data;

struct AE_key
{
	uint8_t key[KEY_LEN];		 // Encryption key
};

#define RHO (KEY_LEN + W * SEED_LEN)
#define NU (IV_LEN + TAG_LEN)

struct delta_token_data
{
	uint8_t seeds[2 * SEED_LEN];
	uint8_t cHat[HEADER_LEN];
};

void PUE_List_KeyGen(AE_key *ae_key);
int PUE_List_EncryptBatch(AE_key *ae_key, uint8_t *messages, uint8_t *ciphertexts, int length, int numMessage);
void PUE_List_DecryptBatch(AE_key *ae_key, uint8_t *ciphertexts, uint8_t *messages, int ctx_length, int numCiphertext);
void PUE_List_ReKeyGen(AE_key *key, AE_key *keyNew); //delta_token_data *delta
void PUE_List_TG(AE_key *keyOld, AE_key *keyNew, uint8_t *cHat, delta_token_data* delta);
void PUE_List_ReEncrypt(delta_token_data *delta, uint8_t *ciphertext, int ctx_length);
void PUE_List_freeBuffers();