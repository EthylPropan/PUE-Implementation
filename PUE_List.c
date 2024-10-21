#include <stdio.h>

#include <stdlib.h>

#include <stdint.h>

#include <string.h>

#include <time.h>

#include <openssl/rand.h>
#include <openssl/sha.h>

#include "aes_ctr.h"

#include "aes_gcm.h"

#include "PUE_List.h"

// Helper Methods
void printHex(uint8_t *arr, int len)
{
    for (int i = 0; i < len; i++)
    {
        printf("%02x", arr[i]);
        if (i + 1 < len)
            printf(" ");
    }
}

void printHexF(uint8_t *arr, int len, char *description)
{
    printf("%s: ", description);
    printHex(arr, len);
    printf("\n");
}

void xorBlocks(uint8_t *in0, uint8_t *in1, uint8_t *out, int ct)
{
    for (int i = 0; i < ct; i++)
    {
        out[i] = in0[i] ^ in1[i];
    }
}

uint8_t *aeRandBuff;
int aeRandBufLen = -1;

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

uint8_t aeIV0[IV_LEN] = {0};
uint8_t *aeMsg0;
int aeMsg0Len = -1;

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

uint8_t *makeZeroesBuffer(int len)
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

void PUE_List_freeBuffers()
{
    free(aeRandBuff);
    free(zeroesBuff);
    free(aeMsg0);
}

void prgEfficient(uint8_t *output, uint8_t *key, int len) 
{
    ctr_encrypt(makeZeroesBuffer(len), len, key, aeIV0, output);
}

void PUE_List_KeyGen(AE_key *ae_key)
{
    RAND_bytes(ae_key->key, KEY_LEN);
}

int PUE_List_EncryptBatch(AE_key *ae_key, uint8_t *messages, uint8_t *ciphertexts, int length, int numMessage)
{
    int ctxLen = length + CTXT_OVERHEAD;
    int totalCtxLen = ctxLen * numMessage;

    for (int i = 0; i < numMessage; i++)
    {
        uint8_t *ciphertext = &ciphertexts[i * ctxLen];
        uint8_t *message = &messages[i * length];

        uint8_t headerContent[HEADER_CONTENT_LEN] = {0}; // set S = 0
        uint8_t *kData = &headerContent[HASH_LEN];
        uint8_t *iv = &ciphertext[HEADER_LEN];
        uint8_t *c = &ciphertext[HEADER_LEN + IV_LEN];
        RAND_bytes(kData, KEY_LEN);
        RAND_bytes(iv, IV_LEN);

        ctr_encrypt(message, length, kData, iv, c);

        // First bits of header content are hash
        SHA256(&ciphertext[HEADER_LEN], length + IV_LEN, headerContent);

        RAND_bytes(ciphertext, IV_LEN);
        gcm_encrypt(headerContent, HEADER_CONTENT_LEN, ae_key->key, ciphertext, IV_LEN, &ciphertext[IV_LEN + TAG_LEN], &ciphertext[IV_LEN]);
    }

    return totalCtxLen;
}

void PUE_List_DecryptBatch(AE_key *ae_key, uint8_t *ciphertexts, uint8_t *messages, int ctx_length, int numCiphertext)
{
    int totalLength = ctx_length * numCiphertext;

    uint8_t *ciphBuff = malloc(totalLength);
    memcpy(ciphBuff, ciphertexts, totalLength);

    int cLen = ctx_length - HEADER_LEN;
    int mLen = cLen - IV_LEN;

    uint8_t *randBuff = makeRandBuffLen(cLen);

    for (int i = 0; i < numCiphertext; i++)
    {
        uint8_t *currCiph = &ciphBuff[ctx_length * i];

        uint8_t headerContent[HEADER_CONTENT_LEN];
        uint8_t *c = &currCiph[HEADER_LEN];

        gcm_decrypt(&currCiph[TAG_LEN + IV_LEN], HEADER_CONTENT_LEN, &currCiph[IV_LEN], ae_key->key, currCiph, IV_LEN,
                    headerContent);

        uint8_t *h = headerContent;

        uint8_t *kData = &headerContent[HASH_LEN];
        uint8_t *S = &headerContent[HASH_LEN + KEY_LEN];

        uint8_t zeroes[SEED_LEN] = {0};

        for (int i = 0; i < P; i++)
        {
            uint8_t *curS = &S[SEED_LEN * i];
            if (!memcmp(zeroes, curS, SEED_LEN))
                break;

            prgEfficient(randBuff, curS, cLen);

            xorBlocks(randBuff, c, c, cLen);
        }

        uint8_t h2[HASH_LEN];
        SHA256(c, cLen, h2);

        if (memcmp(h2, h, HASH_LEN))
        {
            printf("ERROR: Hash not the same.\n");
            return;
        }

        ctr_decrypt(&currCiph[HEADER_LEN + IV_LEN], mLen, kData, &currCiph[HEADER_LEN], &messages[i * mLen]);
    }
}

void PUE_List_TG(AE_key *keyOld, AE_key *keyNew, uint8_t *cHat, delta_token_data *delta)
{
    uint8_t headerContent[HEADER_CONTENT_LEN];

    gcm_decrypt(&cHat[TAG_LEN + IV_LEN], HEADER_CONTENT_LEN, &cHat[IV_LEN], keyOld->key, cHat, IV_LEN,
                headerContent);

    uint8_t *h = headerContent;
    uint8_t *kData = &headerContent[HASH_LEN];
    uint8_t *S = &headerContent[HASH_LEN + KEY_LEN];

    uint8_t zeroes[SEED_LEN] = {0};

    int i;
    uint8_t *curS;
    for (i = 0; i < P; i++)
    {
        curS = &S[SEED_LEN * i];
        if (!memcmp(zeroes, curS, SEED_LEN))
            break;
    }

    if (i == P)
    {
        printf("ERROR: Too many updates.\n");
    }

    RAND_bytes(curS, SEED_LEN);
    memcpy(delta->seeds, curS, SEED_LEN);

    RAND_bytes(delta->cHat, IV_LEN);
    gcm_encrypt(headerContent, HEADER_CONTENT_LEN, keyNew->key, delta->cHat, IV_LEN, &delta->cHat[IV_LEN + TAG_LEN], &delta->cHat[IV_LEN]);
}

void PUE_List_ReKeyGen(AE_key *key, AE_key *keyNew) // delta_token_data *delta
{
    RAND_bytes(keyNew->key, KEY_LEN);
}

void PUE_List_ReEncrypt(delta_token_data *delta, uint8_t *ciphertext, int ctx_length) // For single reencrypt, would need ciphertext offset in PRG.
{
    int cLen = ctx_length - HEADER_LEN;
    int mLen = cLen - IV_LEN;

    uint8_t *c = &ciphertext[HEADER_LEN];

    uint8_t *randBuff = makeRandBuffLen(cLen);

    for (int i = 0; i < 1; i++)
    {
        prgEfficient(randBuff, &delta->seeds[i * SEED_LEN], cLen);

        xorBlocks(randBuff, c, c, cLen);
    }

    memcpy(ciphertext, delta->cHat, HEADER_LEN);
}