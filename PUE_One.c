#include <stdio.h>

#include <stdlib.h>

#include <stdint.h>

#include <string.h>

#include <time.h>

#include <openssl/rand.h>
#include <openssl/sha.h>

#include "aes_ctr.h"

#include "aes_gcm.h"

#include "PUE_One.h"

// Helper Methods
static void printHex(uint8_t *arr, int len)
{
    for (int i = 0; i < len; i++)
    {
        printf("%02x", arr[i]);
        if (i + 1 < len)
            printf(" ");
    }
}

static void printHexF(void *arr, int len, char *description)
{
    printf("%s: ", description);
    printHex((uint8_t *)arr, len);
    printf("\n");
}

static void xorBlocks(uint8_t *in0, uint8_t *in1, uint8_t *out, int ct)
{
    for (int i = 0; i < ct; i++)
    {
        out[i] = in0[i] ^ in1[i];
    }
}

static uint8_t *aeRandBuff;
static int aeRandBufLen = -1;

static uint8_t *makeRandBuffLen(int ctx_length)
{
    if (aeRandBufLen < ctx_length)
    {
        if (aeRandBuff != NULL)
            free(aeRandBuff);
        aeRandBuff = malloc(ctx_length);
        aeRandBufLen = ctx_length;
    }
    return aeRandBuff;
}

static uint8_t aeIV0[IV_LEN] = {0};
static uint8_t *aeMsg0;
static int aeMsg0Len = -1;

static uint8_t *makeBufferA(int msgLen)
{
    if (aeMsg0Len < msgLen)
    {
        if (aeMsg0 != NULL)
            free(aeMsg0);
        aeMsg0 = malloc(msgLen);
        aeMsg0Len = msgLen;
    }
    return aeMsg0;
}

static uint8_t *zeroesBuff;
static int zeroesBuffLen = -1;

static uint8_t *makeZeroesBuffer(int len)
{
    if (zeroesBuffLen < len)
    {
        if (zeroesBuff != NULL)
            free(zeroesBuff);
        zeroesBuff = calloc(len, 1);
        zeroesBuffLen = len;
    }
    return zeroesBuff;
}

void PUE_One_freeBuffers()
{
    free(aeRandBuff);
    free(zeroesBuff);
    free(aeMsg0);
}

static void prgEfficient(uint8_t *output, uint8_t *key, int len) // Efficient version of prgEfficient
{
    ctr_encrypt(makeZeroesBuffer(len), len, key, aeIV0, output);
}

static void myAEEncrypt(AE_key *ae_key, uint8_t *message, AECtxt *ciphertext, int length)
{
    ciphertext->encryptedLen = length;
    RAND_bytes(ciphertext->IV, IV_LEN);
    gcm_encrypt(message, length, ae_key->key, ciphertext->IV, IV_LEN, ciphertext->encryptedBits, ciphertext->Tag);
}

static void myAEDecrypt(AE_key *ae_key, AECtxt *ciphertext, uint8_t *decryptedPlaintext)
{
    gcm_decrypt(ciphertext->encryptedBits, ciphertext->encryptedLen, ciphertext->Tag, ae_key->key, ciphertext->IV, IV_LEN,
                decryptedPlaintext);
}

static void mySEEnc(uint8_t *key, uint8_t *message, SECtxt *ciphertext, int length)
{
    ciphertext->encryptedLen = length;
    RAND_bytes(ciphertext->IV, IV_LEN);
    ctr_encrypt(message, length, key, ciphertext->IV, ciphertext->encryptedBits);
}

static void mySEDec(uint8_t *key, SECtxt *ciphertext, uint8_t *decryptedMessage)
{
    ctr_decrypt(ciphertext->encryptedBits, ciphertext->encryptedLen, key, ciphertext->IV, decryptedMessage);
}

// ######### START MAIN PROGRAM #############

/// @brief Initializes / Resets experiment. Server state needs to be initialized separately.
/// @param ae_key
void PUE_One_KeyGen(AE_key *ae_key)
{
    RAND_bytes(ae_key->key, KEY_LEN);
}

/// @brief Since we only test raw performance, we assume the necessary allocations for the ciphertext have already been done.
/// @param ae_key
/// @param message
/// @param ciphertext
/// @param length
/// @return
int PUE_One_Encrypt(AE_key *ae_key, uint8_t *message, UECtxt *ciphertext, int length)
{
    // Each block of lines of code corresponds to 1 line of pseudocode in figure
    HeaderData header;
    RAND_bytes(header.kData, KEY_LEN);

    mySEEnc(header.kData, message, &ciphertext->c, length);

    SHA256(ciphertext->c.encryptedBits, length, header.hash);

    memset(header.seed, 0, SEED_LEN);

    myAEEncrypt(ae_key, (uint8_t *)&header, &ciphertext->cHat, sizeof(HeaderData));
}

void PUE_One_Decrypt(AE_key *ae_key, UECtxt *ciphertext, uint8_t *message)
{
    // Each block of lines of code corresponds to 1 line of pseudocode in figure
    HeaderData header;
    myAEDecrypt(ae_key, &ciphertext->cHat, (uint8_t *)&header);

    // Ignore integrity check for this performance demo

    makeRandBuffLen(ciphertext->c.encryptedLen);
    uint8_t *workingCopyCiphertext = ciphertext->c.encryptedBits; // To avoid allocating buffer, use message* as working buffer
    for (int i = 0; i < SEED_LEN; i++)
    {
        if (header.seed[i] != 0)
        {
            prgEfficient(aeRandBuff, header.seed, ciphertext->c.encryptedLen);
            xorBlocks(ciphertext->c.encryptedBits, aeRandBuff, message, ciphertext->c.encryptedLen);
            workingCopyCiphertext = message;
            break;
        }
    }

    uint8_t hash2[HASH_LEN];
    SHA256(ciphertext->c.encryptedBits, ciphertext->c.encryptedLen, hash2);
    // Ignore integrity check for this performance demo

    SECtxt toDecrypt; // To avoid allocating buffer, we used message* as working buffer
    toDecrypt.encryptedBits = message;
    toDecrypt.encryptedLen = ciphertext->c.encryptedLen;
    memcpy(toDecrypt.IV, ciphertext->c.IV, IV_LEN);
    mySEDec(header.kData, &toDecrypt, message);
}

/// @brief Takes current key *key and state *state, and returns deltaTilde, keyNew and modifies *state.
/// @param key
/// @param state
/// @param deltaTilde
/// @param keyNew
void PUE_One_ReKeyGen(AE_key *key, AE_key *keyNew)
{
    RAND_bytes(keyNew->key, KEY_LEN);
}

/// @brief Output delta.
/// @param keyOld
/// @param keyNew
/// @param cHat
/// @param deltaTilde
/// @param delta
void PUE_One_TG(AE_key *keyOld, AE_key *keyNew, AECtxt *cHat, delta_token_data *delta)
{
    HeaderData header;
    myAEDecrypt(keyOld, cHat, (uint8_t *)&header);
    memcpy(delta->seed0, header.seed, SEED_LEN);

    // Ignore integrity check for demo

    RAND_bytes(delta->seed1, SEED_LEN); // Ignore \ {0^z} for demo

    memcpy(header.seed, delta->seed1, SEED_LEN);
    myAEEncrypt(keyNew, (uint8_t *)&header, &delta->cHatPrime, sizeof(HeaderData));

    // Tuple create already done
}

void PUE_One_Upd(delta_token_data *delta, UECtxt *ciphertext)
{
    // No parse

    makeRandBuffLen(ciphertext->c.encryptedLen);
    for (int i = 0; i < SEED_LEN; i++)
    {
        if (delta->seed0[i] != 0)
        {
            prgEfficient(aeRandBuff, delta->seed0, ciphertext->c.encryptedLen);
            xorBlocks(ciphertext->c.encryptedBits, aeRandBuff, ciphertext->c.encryptedBits, ciphertext->c.encryptedLen);
            break;
        }
    }

    prgEfficient(aeRandBuff, delta->seed1, ciphertext->c.encryptedLen);
    xorBlocks(ciphertext->c.encryptedBits, aeRandBuff, ciphertext->c.encryptedBits, ciphertext->c.encryptedLen);

    memcpy(&ciphertext->cHat, &delta->cHatPrime, sizeof(AECtxt));
}