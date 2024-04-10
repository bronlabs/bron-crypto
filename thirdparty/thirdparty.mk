thirdparty/boringssl/include/openssl/bn.h:
	git submodule init thirdparty/boringssl

# might not work on windows
thirdparty/boringssl/build/crypto/libcrypto.a: thirdparty/boringssl/include/openssl/bn.h
	cmake thirdparty/boringssl -DCMAKE_BUILD_TYPE=Release -DOPENSSL_SMALL=1 -GNinja -B thirdparty/boringssl/build
	ninja -C thirdparty/boringssl/build -j7 crypto

.PHONY: build-boring
build-boring: thirdparty/boringssl/build/crypto/libcrypto.a

