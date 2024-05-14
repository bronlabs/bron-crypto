BORINGSSL_SUBMODULE := $(KRYPTON_PRIMITIVES_THIRD_PARTY_DIR)/boringssl
BORINGSSL_BUILD:= $(BORINGSSL_SUBMODULE)/build

${BORINGSSL_SUBMODULE}/include/openssl/bn.h:
	git submodule update --init --recursive ${BORINGSSL_SUBMODULE}

# might not work on windows
${BORINGSSL_BUILD}/crypto/libcrypto.a: ${BORINGSSL_SUBMODULE}/include/openssl/bn.h
	cmake ${BORINGSSL_SUBMODULE} -DCMAKE_BUILD_TYPE=Release -DOPENSSL_SMALL=1 -GNinja -B ${BORINGSSL_BUILD}
	ninja -C ${BORINGSSL_BUILD} -j7 crypto

.PHONY: deps-boring
deps-boring: ${BORINGSSL_BUILD}/crypto/libcrypto.a
