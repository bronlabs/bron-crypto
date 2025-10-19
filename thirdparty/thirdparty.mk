BORINGSSL_DIR := $(THIRD_PARTY_DIR)/boringssl
BORINGSSL_BUILD_DIR:= $(BORINGSSL_DIR)/build$(if ${LOCAL},-local)
BORINGSSL_BUILD_ARGS := ""
BORINGSSL_TAG := 0.20250311.0
BORINGSSL_URL := https://boringssl.googlesource.com/boringssl

${BORINGSSL_DIR}/include/openssl/bn.h:
	git clone --depth 1 --branch "${BORINGSSL_TAG}" "${BORINGSSL_URL}" "${BORINGSSL_DIR}"

# might not work on windows
${BORINGSSL_BUILD_DIR}/crypto/libcrypto.a: ${BORINGSSL_DIR}/include/openssl/bn.h
	cmake ${BORINGSSL_DIR} -DCMAKE_BUILD_TYPE=Release ${BORINGSSL_BUILD_ARGS} -DOPENSSL_SMALL=1 -GNinja -B ${BORINGSSL_BUILD_DIR}
	ninja -C ${BORINGSSL_BUILD_DIR} -j7 crypto

.PHONY: deps-boring
deps-boring:
	${RUN_IN_CLAUSE} 'MACOSX_DEPLOYMENT_TARGET=14.0 make ${BORINGSSL_BUILD_DIR}/crypto/libcrypto.a'

deps-boring-ios:
	${RUN_IN_CLAUSE} 'make deps-boring BORINGSSL_BUILD_ARGS="-DCMAKE_OSX_SYSROOT=${sysroot} -DCMAKE_OSX_ARCHITECTURES=${arch}"'
