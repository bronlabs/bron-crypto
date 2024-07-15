BORINGSSL_SUBMODULE := $(KRYPTON_PRIMITIVES_THIRD_PARTY_DIR)/boringssl
BORINGSSL_BUILD:= $(BORINGSSL_SUBMODULE)/build
BORINGSSL_BUILD_ARGS := ""

${BORINGSSL_SUBMODULE}/include/openssl/bn.h:
	git submodule update --init --recursive ${BORINGSSL_SUBMODULE}

# might not work on windows
${BORINGSSL_BUILD}/crypto/libcrypto.a: ${BORINGSSL_SUBMODULE}/include/openssl/bn.h
	cmake ${BORINGSSL_SUBMODULE} -DCMAKE_BUILD_TYPE=Release ${BORINGSSL_BUILD_ARGS} -DOPENSSL_SMALL=1 -GNinja -B ${BORINGSSL_BUILD}
	ninja -C ${BORINGSSL_BUILD} -j7 crypto

.PHONY: deps-boring
deps-boring: ${BORINGSSL_BUILD}/crypto/libcrypto.a

deps-boring-ios:
	make deps-boring BORINGSSL_BUILD_ARGS="-DCMAKE_OSX_SYSROOT=${sysroot} -DCMAKE_OSX_ARCHITECTURES=arm64"
