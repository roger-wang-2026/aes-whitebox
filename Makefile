CFLAGS ?= -Og -ggdb -Wall
CXXFLAGS ?= $(CFLAGS) -std=c++11
PYTHON ?= python3
NTL_PREFIX ?= $(shell brew --prefix ntl 2>/dev/null)
GMP_PREFIX ?= $(shell brew --prefix gmp 2>/dev/null)
CPPFLAGS += $(if $(NTL_PREFIX),-I$(NTL_PREFIX)/include) $(if $(GMP_PREFIX),-I$(GMP_PREFIX)/include)
LDFLAGS += $(if $(NTL_PREFIX),-L$(NTL_PREFIX)/lib) $(if $(GMP_PREFIX),-L$(GMP_PREFIX)/lib)
NTL_PREFIX := $(NTL_PREFIX)
GMP_PREFIX := $(GMP_PREFIX)
LDLIBS ?= -lntl -lgmp -pthread
.DEFAULT_GOAL := all

# All tests were taken from NIST, 2001 test vectors:
# https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

TEST_PLAIN = 6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710

CBC_TEST_IV = 000102030405060708090a0b0c0d0e0f
AES128_CBC_TEST_CIPHER = 7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7
AES192_CBC_TEST_CIPHER = 4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd
AES256_CBC_TEST_CIPHER = f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b

AES128_KEY             = 2b7e151628aed2a6abf7158809cf4f3c
AES128_CFB_TEST_CIPHER = 3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6
AES128_CFB_TEST_IV     = 000102030405060708090a0b0c0d0e0f
AES128_OFB_TEST_CIPHER = 3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed8259740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e
AES128_OFB_TEST_IV     = 000102030405060708090a0b0c0d0e0f
AES128_CTR_TEST_CIPHER = 874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee
AES128_CTR_TEST_NONCE  = f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff

AES192_KEY             = 8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b
AES192_CFB_TEST_CIPHER = cdc80d6fddf18cab34c25909c99a417467ce7f7f81173621961a2b70171d3d7a2e1e8a1dd59b88b1c8e60fed1efac4c9c05f9f9ca9834fa042ae8fba584b09ff
AES192_CFB_TEST_IV     = 000102030405060708090a0b0c0d0e0f
AES192_OFB_TEST_CIPHER = cdc80d6fddf18cab34c25909c99a4174fcc28b8d4c63837c09e81700c11004018d9a9aeac0f6596f559c6d4daf59a5f26d9f200857ca6c3e9cac524bd9acc92a
AES192_OFB_TEST_IV     = 000102030405060708090a0b0c0d0e0f
AES192_CTR_TEST_CIPHER = 1abc932417521ca24f2b0459fe7e6e0b090339ec0aa6faefd5ccc2c6f4ce8e941e36b26bd1ebc670d1bd1d665620abf74f78a7f6d29809585a97daec58c6b050
AES192_CTR_TEST_NONCE  = f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff

AES256_KEY             = 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
AES256_CFB_TEST_CIPHER = dc7e84bfda79164b7ecd8486985d386039ffed143b28b1c832113c6331e5407bdf10132415e54b92a13ed0a8267ae2f975a385741ab9cef82031623d55b1e471
AES256_CFB_TEST_IV     = 000102030405060708090a0b0c0d0e0f
AES256_OFB_TEST_CIPHER = dc7e84bfda79164b7ecd8486985d38604febdc6740d20b3ac88f6ad82a4fb08d71ab47a086e86eedf39d1c5bba97c4080126141d67f37be8538f5a8be740e484
AES256_OFB_TEST_IV     = 000102030405060708090a0b0c0d0e0f
AES256_CTR_TEST_CIPHER = 601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6
AES256_CTR_TEST_NONCE  = f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff

.PHONY: all test test-decrypt clean equivalence equivalence-decrypt robustness dca-prepare dca-preflight FORCE aes128_tests aes192_tests aes256_tests
FORCE:
all: test

test: aes128_tests aes192_tests aes256_tests robustness

build:
	mkdir -p $@

build/aes_whitebox_compiler.o: aes_whitebox_compiler.cc aes_private.h hex.h | build
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -MMD -MP -c $< -o $@

build/aes_whitebox_compiler: build/aes_whitebox_compiler.o
	$(CXX) $(LDFLAGS) $^ $(LDLIBS) -o $@

build/aes.o: aes.cc aes.h aes_private.h | build
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -MMD -MP -c $< -o $@

libaes.a: build/aes.o
	$(AR) $(ARFLAGS) $@ $^

# A stamp owns both outputs, avoiding competing generator invocations in make -j.
define AES_RULES
build/aes$(1):
	mkdir -p $$@

build/aes$(1)/tables.stamp: build/aes_whitebox_compiler Makefile $$(if $$(and $$(wildcard build/aes$(1)/aes_whitebox_tables.cc),$$(wildcard build/aes$(1)/external_encodings.cc)),,FORCE) | build/aes$(1)
	@if test ! -f $$@ || test build/aes_whitebox_compiler -nt $$@ || test Makefile -nt $$@ || test ! -s build/aes$(1)/aes_whitebox_tables.cc || test ! -s build/aes$(1)/external_encodings.cc; then \
	  ./build/aes_whitebox_compiler aes$(1) $$(AES$(1)_KEY) --output build/aes$(1)/aes_whitebox_tables.cc --helpers build/aes$(1)/external_encodings.cc && touch $$@; \
	fi

build/aes$(1)/aes_whitebox_tables.cc build/aes$(1)/external_encodings.cc: | build/aes$(1)/tables.stamp
	@test -s $$@

build/aes$(1)/aes_whitebox.o: aes_whitebox.cc aes_whitebox.h aes_whitebox_internal.h build/aes$(1)/tables.stamp
	$$(CXX) $$(CPPFLAGS) $$(CXXFLAGS) -Ibuild/aes$(1) -MMD -MP -c $$< -o $$@

build/aes$(1)/external_encodings.o: build/aes$(1)/external_encodings.cc build/aes$(1)/tables.stamp
	$$(CXX) $$(CPPFLAGS) $$(CXXFLAGS) -MMD -MP -c build/aes$(1)/external_encodings.cc -o $$@

build/aes$(1)/aes_tests.o: aes_tests.c aes_whitebox.h hex.h aunit.h | build/aes$(1)
	$$(CC) $$(CPPFLAGS) $$(CFLAGS) -MMD -MP -c $$< -o $$@

build/aes$(1)/aes_tests: build/aes$(1)/aes_whitebox.o build/aes$(1)/external_encodings.o build/aes$(1)/aes_tests.o
	$$(CXX) $$(LDFLAGS) $$^ -o $$@

build/aes$(1)/cbc_tests.o: tests/cbc_tests.c aes_whitebox.h hex.h aunit.h | build/aes$(1)
	$$(CC) $$(CPPFLAGS) $$(CFLAGS) -I. -MMD -MP -c $$< -o $$@

build/aes$(1)/cbc_tests: build/aes$(1)/aes_whitebox.o build/aes$(1)/external_encodings.o build/aes$(1)/cbc_tests.o
	$$(CXX) $$(LDFLAGS) $$^ -o $$@

aes$(1)_tests: build/aes$(1)/aes_tests build/aes$(1)/cbc_tests
	./$$< cfb $$(TEST_PLAIN) $$(AES$(1)_CFB_TEST_IV) $$(AES$(1)_CFB_TEST_CIPHER)
	./$$< ofb $$(TEST_PLAIN) $$(AES$(1)_OFB_TEST_IV) $$(AES$(1)_OFB_TEST_CIPHER)
	./$$< ctr $$(TEST_PLAIN) $$(AES$(1)_CTR_TEST_NONCE) $$(AES$(1)_CTR_TEST_CIPHER)
	./build/aes$(1)/cbc_tests $$(TEST_PLAIN) $$(CBC_TEST_IV) $$(AES$(1)_CBC_TEST_CIPHER)

build/aes$(1)/decrypt:
	mkdir -p $$@

build/aes$(1)/decrypt/tables.stamp: build/aes_whitebox_compiler Makefile $$(if $$(and $$(wildcard build/aes$(1)/decrypt/aes_whitebox_decrypt_tables.cc),$$(wildcard build/aes$(1)/decrypt/external_encodings.cc)),,FORCE) | build/aes$(1)/decrypt
	@if test ! -f $$@ || test build/aes_whitebox_compiler -nt $$@ || test Makefile -nt $$@ || test ! -s build/aes$(1)/decrypt/aes_whitebox_decrypt_tables.cc || test ! -s build/aes$(1)/decrypt/external_encodings.cc; then \
	  ./build/aes_whitebox_compiler aes$(1) $$(AES$(1)_KEY) --direction decrypt --output build/aes$(1)/decrypt/aes_whitebox_decrypt_tables.cc --helpers build/aes$(1)/decrypt/external_encodings.cc && touch $$@; \
	fi

build/aes$(1)/decrypt/aes_whitebox_decrypt_tables.cc build/aes$(1)/decrypt/external_encodings.cc: | build/aes$(1)/decrypt/tables.stamp
	@test -s $$@

build/aes$(1)/decrypt/aes_whitebox_decrypt.o: aes_whitebox_decrypt.cc aes_whitebox.h aes_whitebox_internal.h build/aes$(1)/decrypt/tables.stamp
	$$(CXX) $$(CPPFLAGS) $$(CXXFLAGS) -Ibuild/aes$(1)/decrypt -MMD -MP -c $$< -o $$@

build/aes$(1)/decrypt/external_encodings.o: build/aes$(1)/decrypt/external_encodings.cc build/aes$(1)/decrypt/tables.stamp
	$$(CXX) $$(CPPFLAGS) $$(CXXFLAGS) -MMD -MP -c $$< -o $$@

build/aes$(1)/decrypt/cbc_tests.o: tests/cbc_decrypt_tests.c aes_whitebox.h hex.h aunit.h | build/aes$(1)/decrypt
	$$(CC) $$(CPPFLAGS) $$(CFLAGS) -I. -MMD -MP -c $$< -o $$@

build/aes$(1)/decrypt/cbc_tests: build/aes$(1)/decrypt/aes_whitebox_decrypt.o build/aes$(1)/decrypt/external_encodings.o build/aes$(1)/decrypt/cbc_tests.o
	$$(CXX) $$(LDFLAGS) $$^ -o $$@

.PHONY: aes$(1)_decrypt_tests
aes$(1)_decrypt_tests: build/aes$(1)/decrypt/cbc_tests
	./$$< $$(TEST_PLAIN) $$(CBC_TEST_IV) $$(AES$(1)_CBC_TEST_CIPHER)

endef

$(foreach bits,128 192 256,$(eval $(call AES_RULES,$(bits))))

test-decrypt: aes128_decrypt_tests aes192_decrypt_tests aes256_decrypt_tests

equivalence-decrypt: build/aes_whitebox_compiler
	$(PYTHON) tests/decrypt_equivalence.py

robustness: build/aes_whitebox_compiler build/aes128/aes_tests
	$(PYTHON) tests/robustness.py

equivalence: build/aes_whitebox_compiler
	$(PYTHON) tests/equivalence.py

dca-prepare: build/aes_whitebox_compiler
	$(PYTHON) security/prepare_dca.py

dca-preflight:
	$(PYTHON) security/dca_preflight.py

clean:
	rm -rf build
	rm -f libaes.a

-include $(wildcard build/*.d build/aes*/*.d build/aes*/decrypt/*.d)
