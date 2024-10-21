#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <string.h>
#include <time.h>
#include <openssl/rand.h>

#include "aes_ctr.h"
#include "aes_gcm.h"
#include "PUE_List.h"

//  Windows
#ifdef _WIN32

#include <intrin.h>
uint64_t rdtsc()
{
    return __rdtsc();
}

//  Linux/GCC
#else

uint64_t rdtsc()
{
    unsigned int lo, hi;
    __asm__ __volatile__("rdtsc"
                         : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

#endif

#define CYCLES_DIVISOR 1
#define CYCLES_UNIT_NAME "Cy"

// Usage: test_XXX numCiphertext totalReEncrypts plaintextSize
int main(int argc, char **argv)
{
    printf("Start...\n");

    int size = 496;
    int runs = 1;
    int total_re_encrypts = 20;
    int numCiphertext = 1;

    if (argc > 1)
        numCiphertext = atoi(argv[1]);

    if (argc > 2)
        total_re_encrypts = atoi(argv[2]);

    if (argc > 3)
        size = atoi(argv[3]);

    if (argc > 4)
        runs = atoi(argv[4]);

    int ctxtSize = size + CTXT_OVERHEAD;
    int buffer_length = ctxtSize * numCiphertext;
    printf("Buffer length is %i * %d\n", numCiphertext, ctxtSize);
    int totalPlaintextSize = size * numCiphertext;
    uint8_t *message = (int8_t *)malloc(totalPlaintextSize);
    RAND_bytes(message, totalPlaintextSize);
    uint8_t *decrypted_message = (int8_t *)malloc(totalPlaintextSize);

    uint8_t *ciphertext = (int8_t *)malloc(buffer_length);

    AE_key ae_key, ae_key_new;

    uint64_t gen_cycles = 0;
    uint64_t encrypt_cycles = 0;
    uint64_t regen_cycles = 0;
    uint64_t re_encrypt_cycles = 0;
    uint64_t *decrypt_cycles = calloc(total_re_encrypts, sizeof(uint64_t));

    uint64_t begin;
    uint64_t end;
    delta_token_data* deltas = calloc(numCiphertext, sizeof(delta_token_data));

    for (int run = 0; run < runs; run++)
    {
        // AE_KeyGen
        begin = rdtsc();
        PUE_List_KeyGen(&ae_key);
        end = rdtsc();
        gen_cycles += (end - begin);

        // AE_Encrypt
        begin = rdtsc();
        PUE_List_EncryptBatch(&ae_key, message, ciphertext, size, numCiphertext);

        end = rdtsc();
        encrypt_cycles += (end - begin);

        for (int re_encrypts = 0; re_encrypts < total_re_encrypts; re_encrypts++)
        {
            // ReKeyGen
            begin = rdtsc();
            PUE_List_ReKeyGen(&ae_key, &ae_key_new);
            for(int ciphInd = 0; ciphInd < numCiphertext; ciphInd++)
            {
                PUE_List_TG(&ae_key, &ae_key_new, &ciphertext[ctxtSize * ciphInd], &deltas[sizeof(delta_token_data) * ciphInd]);
            }
            end = rdtsc();
            regen_cycles += (end - begin);

            // ReEncrypt
            begin = rdtsc();
            for (int ciphInd = 0; ciphInd < numCiphertext; ciphInd++)
                PUE_List_ReEncrypt(&deltas[sizeof(delta_token_data) * ciphInd], &ciphertext[ciphInd * ctxtSize], ctxtSize);
            end = rdtsc();
            re_encrypt_cycles += (end - begin);

            memcpy(&ae_key, &ae_key_new, sizeof(AE_key));

            // AE_Decrypt
            begin = rdtsc();
            PUE_List_DecryptBatch(&ae_key, ciphertext, decrypted_message, ctxtSize, numCiphertext);
            end = rdtsc();
            decrypt_cycles[re_encrypts] += (end - begin);

            if (memcmp(message, decrypted_message, totalPlaintextSize) != 0)
                printf("Decryption error.\n");
        }
    }

    gen_cycles /= CYCLES_DIVISOR;
    encrypt_cycles /= CYCLES_DIVISOR;
    regen_cycles /= CYCLES_DIVISOR;
    re_encrypt_cycles /= CYCLES_DIVISOR;
    for (int i = 0; i < total_re_encrypts; i++)
        decrypt_cycles[i] /= CYCLES_DIVISOR;

    printf("###### PUE_List (p=%i) ######\nSize:%d Runs:%u NumCiphertext:%i ReEncrypts:%i\n <function>\ttot(%s)\t<# calls>\n gen_key:\t%lu\t%d\n encrypt:\t%lu\t%d\n regen_key:\t%lu\t%d\n re_encrypt:\t%lu\t%d\n first_decrypt:\t%lu\t%d\t\n last_decrypt:\t%lu\t%d\t\n\n",
           P, size, runs, numCiphertext, total_re_encrypts, CYCLES_UNIT_NAME,
           gen_cycles, runs,
           encrypt_cycles, runs * numCiphertext,
           regen_cycles, (runs * total_re_encrypts),
           re_encrypt_cycles, (runs * total_re_encrypts * numCiphertext),
           decrypt_cycles[0], runs * numCiphertext,
           decrypt_cycles[total_re_encrypts - 1], runs * numCiphertext);

    printf("Decrypt Data\n");
    for (int i = 0; i < total_re_encrypts; i++)
        printf("%lu, ", decrypt_cycles[i]);
    printf("\n");

    free(message);
    free(decrypted_message);
    free(ciphertext);
    PUE_List_freeBuffers();
    printf("Done...\n");
}