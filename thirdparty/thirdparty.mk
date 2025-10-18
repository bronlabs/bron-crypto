BORINGSSL_SUBMODULE := $(THIRD_PARTY_DIR)/boringssl
BORINGSSL_BUILD:= $(BORINGSSL_SUBMODULE)/build$(if ${LOCAL},-local)
BORINGSSL_BUILD_ARGS := ""

${BORINGSSL_SUBMODULE}/include/openssl/bn.h:
	git clone https://boringssl.googlesource.com/boringssl ${BORINGSSL_SUBMODULE}
	cd ${BORINGSSL_SUBMODULE} && git checkout f94f3ed

# might not work on windows
${BORINGSSL_BUILD}/crypto/libcrypto.a: ${BORINGSSL_SUBMODULE}/include/openssl/bn.h
	cmake ${BORINGSSL_SUBMODULE} -DCMAKE_BUILD_TYPE=Release ${BORINGSSL_BUILD_ARGS} -DOPENSSL_SMALL=1 -GNinja -B ${BORINGSSL_BUILD}
	ninja -C ${BORINGSSL_BUILD} -j7 crypto

.PHONY: deps-boring
deps-boring:
	${RUN_IN_CLAUSE} 'MACOSX_DEPLOYMENT_TARGET=14.0 make ${BORINGSSL_BUILD}/crypto/libcrypto.a'

deps-boring-ios:
	${RUN_IN_CLAUSE} 'make deps-boring BORINGSSL_BUILD_ARGS="-DCMAKE_OSX_SYSROOT=${sysroot} -DCMAKE_OSX_ARCHITECTURES=${arch}"'
