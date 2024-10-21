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
typedef struct delta_token_data delta_token_data;
typedef struct AECtxt AECtxt;
typedef struct SECtxt SECtxt;
typedef struct UECtxt UECtxt;
typedef struct HeaderData HeaderData;

struct HeaderData
{
    uint8_t hash[HASH_LEN];
    uint8_t kData[KEY_LEN];
	uint8_t seed[SEED_LEN];
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

struct UECtxt
{
	AECtxt cHat;
	SECtxt c;
};

struct delta_token_data
{
	AECtxt cHatPrime;
	uint8_t seed0[SEED_LEN];
	uint8_t seed1[SEED_LEN];
};

void PUE_One_KeyGen(AE_key *ae_key);
int PUE_One_Encrypt(AE_key *ae_key, uint8_t *message, UECtxt *ciphertext, int length);
void PUE_One_Decrypt(AE_key *ae_key, UECtxt *ciphertext, uint8_t *message);
void PUE_One_ReKeyGen(AE_key *key, AE_key *keyNew);
void PUE_One_TG(AE_key *keyOld, AE_key *keyNew, AECtxt *cHat, delta_token_data *delta);
void PUE_One_Upd(delta_token_data *delta, UECtxt *ciphertext);
void PUE_One_freeBuffers();