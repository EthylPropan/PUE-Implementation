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

typedef struct AE_key AE_key;
typedef struct AE_ctx_header AE_ctx_header;
typedef struct ct_hat_data ct_hat_data;
typedef struct ct_hat_data_en ct_hat_data_en;
typedef struct AE_ctx_len AE_ctx_len;
typedef struct delta_token_data delta_token_data;
typedef struct AECtxt AECtxt;
typedef struct SECtxt SECtxt;
typedef struct UECtxtHeader UECtxtHeader;
typedef struct UECtxt UECtxt;
typedef struct ServerState ServerState;
typedef struct deltaTildeData deltaTildeData;
typedef struct HeaderData HeaderData;

struct HeaderData
{
    uint8_t hash[HASH_LEN];
    uint8_t kData[KEY_LEN];
    uint8_t seedToken[SEED_LEN];
    int e;
    int o;
};

struct AE_key
{
	uint8_t key[KEY_LEN]; // Encryption key
};

struct AECtxt
{
	uint8_t IV[IV_LEN];
	uint8_t Tag[TAG_LEN];
	int encryptedLen;
	uint8_t *encryptedBits;
};

struct SECtxt
{
	uint8_t IV[IV_LEN];
	int encryptedLen;
	uint8_t *encryptedBits;
};

struct UECtxtHeader
{
	uint8_t seedToken[SEED_LEN];
	AECtxt cHatMain;
};

struct UECtxt
{
	UECtxtHeader cHat;
	SECtxt c;
};

struct delta_token_data
{
	UECtxtHeader cHatPrime;
	int o;
};

struct deltaTildeData
{
	uint8_t seed[SEED_LEN];
};

struct ServerState
{
	int seedNum; // Not encrypted, known to adversary in model
	AECtxt SeedsCtxt;
};

void PUE_SState_KeyGen(AE_key *ae_key);
int PUE_SState_Encrypt(AE_key *ae_key, uint8_t *message, UECtxt *ciphertext, int length);
void PUE_SState_Decrypt(AE_key *ae_key, UECtxt *ciphertext, ServerState *state, uint8_t *message);
void PUE_SState_ReKeyGen(AE_key *key, ServerState *state, deltaTildeData *deltaTilde, AE_key *keyNew);
void PUE_SState_TG(AE_key *keyOld, AE_key *keyNew, UECtxtHeader *cHat, deltaTildeData *deltaTilde, delta_token_data *delta);
void PUE_SState_Upd(deltaTildeData *deltaTilde, delta_token_data *delta, UECtxt *ciphertext);
void PUE_SState_freeBuffers();