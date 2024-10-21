#include <stdio.h>

#include <stdlib.h>

#include <stdint.h>

#include <string.h>

#include <time.h>

#include <openssl/rand.h>
#include <openssl/sha.h>

#include "aes_ctr.h"

#include "aes_gcm.h"

#include "PUE_State.h"

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

void PUE_SState_freeBuffers()
{
    free(aeRandBuff);
    free(zeroesBuff);
    free(aeMsg0);
}

static void prgEfficient(uint8_t *output, uint8_t *key, int len) // Efficient version of prgEfficient
{
    ctr_encrypt(makeZeroesBuffer(len), len, key, aeIV0, output);
}

// ######### START MAIN PROGRAM #############
static int CState_e = 0;
static int CState_off = 0;

/// @brief Initializes / Resets experiment. Server state needs to be initialized separately.
/// @param ae_key
void PUE_SState_KeyGen(AE_key *ae_key)
{
    CState_e = 0;
    CState_off = 0;
    RAND_bytes(ae_key->key, KEY_LEN);
}

void myAEEncrypt(AE_key *ae_key, uint8_t *message, AECtxt *ciphertext, int length)
{
    ciphertext->encryptedLen = length;
    RAND_bytes(ciphertext->IV, IV_LEN);
    gcm_encrypt(message, length, ae_key->key, ciphertext->IV, IV_LEN, ciphertext->encryptedBits, ciphertext->Tag);
}

void myAEDecrypt(AE_key *ae_key, AECtxt *ciphertext, uint8_t *decryptedPlaintext)
{
    gcm_decrypt(ciphertext->encryptedBits, ciphertext->encryptedLen, ciphertext->Tag, ae_key->key, ciphertext->IV, IV_LEN,
                decryptedPlaintext);
}

void mySEEnc(uint8_t *key, uint8_t *message, SECtxt *ciphertext, int length)
{
    ciphertext->encryptedLen = length;
    RAND_bytes(ciphertext->IV, IV_LEN);
    ctr_encrypt(message, length, key, ciphertext->IV, ciphertext->encryptedBits);
}

void mySEDec(uint8_t *key, SECtxt *ciphertext, uint8_t *decryptedMessage)
{
    ctr_decrypt(ciphertext->encryptedBits, ciphertext->encryptedLen, key, ciphertext->IV, decryptedMessage);
}

/// @brief Since we only test raw performance, we assume the necessary allocations for the ciphertext have already been done.
/// @param ae_key
/// @param message
/// @param ciphertext
/// @param length
/// @return
int PUE_SState_Encrypt(AE_key *ae_key, uint8_t *message, UECtxt *ciphertext, int length)
{
    // Each block of lines of code corresponds to 1 line of pseudocode in figure
    HeaderData header;

    RAND_bytes(header.kData, KEY_LEN);

    mySEEnc(header.kData, message, &ciphertext->c, length);

    header.e = CState_e;

    header.o = CState_off;

    RAND_bytes(header.seedToken, SEED_LEN);

    SHA256(ciphertext->c.encryptedBits, length, header.hash);
    myAEEncrypt(ae_key, (uint8_t *)&header, &ciphertext->cHat.cHatMain, sizeof(HeaderData));

    memcpy(ciphertext->cHat.seedToken, header.seedToken, SEED_LEN);

    CState_off += length;
}

void PUE_SState_Decrypt(AE_key *ae_key, UECtxt *ciphertext, ServerState *state, uint8_t *message)
{
    // Each block of lines of code corresponds to 1 line of pseudocode in figure
    // No line 1 (parsing)

    HeaderData header;
    myAEDecrypt(ae_key, &ciphertext->cHat.cHatMain, (uint8_t *)&header);

    // Ignore integrity check for this performance demo

    uint8_t *seeds = makeBufferA(SEED_LEN * state->seedNum);
    myAEDecrypt(ae_key, &state->SeedsCtxt, seeds);

    // No seed list parsing

    makeRandBuffLen(ciphertext->c.encryptedLen);
    uint8_t *workingCopyCiphertext = ciphertext->c.encryptedBits; // To avoid allocating buffer, use message* as working buffer
    for (int i = header.e; i < state->seedNum; i++) // -1 to indices for 0 based seed array
    {
        prgEfficient(aeRandBuff, &seeds[SEED_LEN * i], ciphertext->c.encryptedLen); // Ignore offset header.o, always 0 for this performance test
        xorBlocks(workingCopyCiphertext, aeRandBuff, message, ciphertext->c.encryptedLen);
        workingCopyCiphertext = message;
    }

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
void PUE_SState_ReKeyGen(AE_key *key, ServerState *state, deltaTildeData *deltaTilde, AE_key *keyNew)
{
    RAND_bytes(keyNew->key, KEY_LEN);

    uint8_t *seeds = makeBufferA(SEED_LEN * (state->seedNum + 1));
    if (state->seedNum > 0)
        myAEDecrypt(key, &state->SeedsCtxt, seeds);

    // No parsing

    RAND_bytes(&seeds[SEED_LEN * state->seedNum], SEED_LEN);

    // No adding to list

    memcpy(deltaTilde->seed, &seeds[SEED_LEN * state->seedNum], SEED_LEN);

    if (state->seedNum > 0)
        free(state->SeedsCtxt.encryptedBits);
    state->seedNum++;
    state->SeedsCtxt.encryptedBits = (uint8_t *)malloc(SEED_LEN * state->seedNum);
    myAEEncrypt(keyNew, seeds, &state->SeedsCtxt, SEED_LEN * state->seedNum);

    CState_e++;
}

/// @brief Output delta.
/// @param keyOld
/// @param keyNew
/// @param cHat
/// @param deltaTilde
/// @param delta
void PUE_SState_TG(AE_key *keyOld, AE_key *keyNew, UECtxtHeader *cHat, deltaTildeData *deltaTilde, delta_token_data *delta)
{
    // No parsing

    HeaderData header;
    myAEDecrypt(keyOld, &cHat->cHatMain, (uint8_t *)&header);

    RAND_bytes(delta->cHatPrime.seedToken, SEED_LEN);

    memcpy(header.seedToken, delta->cHatPrime.seedToken, SEED_LEN);
    myAEEncrypt(keyNew, (uint8_t *)&header, &delta->cHatPrime.cHatMain, sizeof(HeaderData));

    delta->o = header.o;

    makeRandBuffLen(sizeof(delta_token_data) + sizeof(HeaderData));
    prgEfficient(aeRandBuff, cHat->seedToken, sizeof(delta_token_data) + sizeof(HeaderData));
    xorBlocks(delta->cHatPrime.cHatMain.encryptedBits, aeRandBuff, delta->cHatPrime.cHatMain.encryptedBits, sizeof(HeaderData));
    xorBlocks((uint8_t *)delta, &aeRandBuff[sizeof(HeaderData)], (uint8_t *)delta, sizeof(delta_token_data));
}

void PUE_SState_Upd(deltaTildeData *deltaTilde, delta_token_data *delta, UECtxt *ciphertext)
{
    // No parse

    makeRandBuffLen(sizeof(delta_token_data) + sizeof(HeaderData));
    prgEfficient(aeRandBuff, ciphertext->cHat.seedToken, sizeof(delta_token_data) + sizeof(HeaderData));
    xorBlocks((uint8_t *)delta, &aeRandBuff[sizeof(HeaderData)], (uint8_t *)delta, sizeof(delta_token_data));
    xorBlocks(delta->cHatPrime.cHatMain.encryptedBits, aeRandBuff, delta->cHatPrime.cHatMain.encryptedBits, sizeof(HeaderData));

    // No parse

    // No parse

    makeRandBuffLen(ciphertext->c.encryptedLen);
    prgEfficient(aeRandBuff, deltaTilde->seed, ciphertext->c.encryptedLen);
    xorBlocks(ciphertext->c.encryptedBits, aeRandBuff, ciphertext->c.encryptedBits, ciphertext->c.encryptedLen);

    memcpy(&ciphertext->cHat, &delta->cHatPrime, sizeof(UECtxtHeader));
}