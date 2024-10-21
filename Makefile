CC = /usr/bin/gcc
NISTFLAGS = -O3 -fomit-frame-pointer -march=native -fPIC -no-pie
UTILS_DIR = ./utils

DEPS = $(UTILS_DIR)/aes_ctr.c $(UTILS_DIR)/aes_ctr.h $(UTILS_DIR)/aes_gcm.c $(UTILS_DIR)/aes_gcm.h PUE_List.c PUE_List.h PUE_State.c PUE_State.h PUE_One.c PUE_One.h

all: PUE_List PUE_SState PUE_One

PUE_List: $(DEPS)
	$(CC) $(NISTFLAGS) -I$(UTILS_DIR) $(DEPS) -msse2avx -mavx2 test_PUE_List.c -o test_PUE_List -lcrypto

PUE_SState: $(DEPS)
	$(CC) $(NISTFLAGS) -I$(UTILS_DIR) $(DEPS) -msse2avx -mavx2 test_PUE_State.c -o test_PUE_State -lcrypto

PUE_One: $(DEPS)
	$(CC) $(NISTFLAGS) -I$(UTILS_DIR) $(DEPS) -msse2avx -mavx2 test_PUE_One.c -o test_PUE_One -lcrypto

.PHONY: clean

clean:
	-rm PUE_List PUE_SState PUE_One
