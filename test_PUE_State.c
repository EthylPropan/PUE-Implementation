#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <string.h>
#include <time.h>
#include <openssl/rand.h>

#include "aes_ctr.h"
#include "aes_gcm.h"
#include "PUE_State.h"

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

    printf("Buffer length is ?\n"); // %i * %d\n", numCiphertext, ctxtSize);
    int totalPlaintextSize = size * numCiphertext;
    uint8_t *message = (int8_t *)malloc(totalPlaintextSize);
    RAND_bytes(message, totalPlaintextSize);
    uint8_t *decrypted_message = (int8_t *)malloc(totalPlaintextSize);

    // ######### APPL SPECIFIC INIT
    AE_key ae_key, ae_key_new;
    UECtxt ueCiphertext;
    ueCiphertext.c.encryptedBits = (int8_t *)malloc(totalPlaintextSize);
    ueCiphertext.cHat.cHatMain.encryptedBits = (int8_t *)malloc(sizeof(HeaderData));
    ServerState serverState;
    deltaTildeData deltaTilde;
    delta_token_data delta;
    delta.cHatPrime.cHatMain.encryptedBits = (int8_t *)malloc(sizeof(HeaderData));
    // ######### END APPL SPECIFIC INIT

    uint64_t gen_cycles = 0;
    uint64_t encrypt_cycles = 0;
    uint64_t regen_cycles = 0;
    uint64_t re_encrypt_cycles = 0;
    uint64_t *decrypt_cycles = calloc(total_re_encrypts, sizeof(uint64_t));

    uint64_t begin;
    uint64_t end;
    delta_token_data *deltas = calloc(numCiphertext, sizeof(delta_token_data));

    for (int run = 0; run < runs; run++)
    {
        // AE_KeyGen
        begin = rdtsc();
        PUE_SState_KeyGen(&ae_key);
        end = rdtsc();
        gen_cycles += (end - begin);

        // AE_Encrypt
        begin = rdtsc();
        PUE_SState_Encrypt(&ae_key, message, &ueCiphertext, size);
        end = rdtsc();
        encrypt_cycles += (end - begin);

        for (int re_encrypts = 0; re_encrypts < total_re_encrypts; re_encrypts++)
        {
            // ReKeyGen
            begin = rdtsc();
            PUE_SState_ReKeyGen(&ae_key, &serverState, &deltaTilde, &ae_key_new);
            PUE_SState_TG(&ae_key, &ae_key_new, &ueCiphertext.cHat, &deltaTilde, &delta);
            end = rdtsc();
            regen_cycles += (end - begin);
           
            // ReEncrypt
            begin = rdtsc();
            PUE_SState_Upd(&deltaTilde, &delta, &ueCiphertext);
            end = rdtsc();
            re_encrypt_cycles += (end - begin);

            memcpy(&ae_key, &ae_key_new, sizeof(AE_key));

            // AE_Decrypt
            begin = rdtsc();
            PUE_SState_Decrypt(&ae_key, &ueCiphertext, &serverState, decrypted_message);
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

    printf("###### PUE_State ######\nSize:%d Runs:%u NumCiphertext:%i ReEncrypts:%i\n <function>\ttot(%s)\t<# calls>\n gen_key:\t%lu\t%d\n encrypt:\t%lu\t%d\n regen_key:\t%lu\t%d\n re_encrypt:\t%lu\t%d\n first_decrypt:\t%lu\t%d\t\n last_decrypt:\t%lu\t%d\t\n\n",
           size, runs, numCiphertext, total_re_encrypts, CYCLES_UNIT_NAME,
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
    free(ueCiphertext.c.encryptedBits);
    free(ueCiphertext.cHat.cHatMain.encryptedBits);
    free(serverState.SeedsCtxt.encryptedBits);
    PUE_SState_freeBuffers();
    printf("Done...\n");
}