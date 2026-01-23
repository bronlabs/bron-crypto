BRON_CRYPTO_HOME := $(dir $(lastword $(MAKEFILE_LIST)))
BORINGSSL_TAG := 0.20251124.0
BORINGSSL_URL := https://github.com/google/boringssl
BORINGSSL_HOME := ${BRON_CRYPTO_HOME}/thirdparty/boringssl/
BORINGSSL_INCLUDE := ${BORINGSSL_HOME}/include
BORINGSSL_LIB := ${BORINGSSL_HOME}/${BUILD_PREFIX}build/

.PHONY: all
all: build sbom

${BORINGSSL_INCLUDE}/openssl:
	git clone --depth 1 --branch "${BORINGSSL_TAG}" "${BORINGSSL_URL}" "${BORINGSSL_HOME}"

${BORINGSSL_LIB}/libcrypto.a: ${BORINGSSL_INCLUDE}/openssl
	cmake "${BORINGSSL_HOME}" -DCMAKE_BUILD_TYPE=Release -DOPENSSL_SMALL=1 -GNinja -B "${BORINGSSL_LIB}"
	ninja -C ${BORINGSSL_LIB} crypto

.PHONY: build-boringssl
build-boringssl: ${BORINGSSL_LIB}/libcrypto.a

.PHONY: generate
generate:
	go generate "${BRON_CRYPTO_HOME}/..."

.PHONY: build
build: build-boringssl
	CGO_CFLAGS="-I$(abspath ${BORINGSSL_INCLUDE})" CGO_LDFLAGS="-L$(abspath ${BORINGSSL_LIB}) -lcrypto" go build "${BRON_CRYPTO_HOME}/..."

.PHONY: test
test: build-boringssl
	CGO_CFLAGS="-I$(abspath ${BORINGSSL_INCLUDE})" CGO_LDFLAGS="-L$(abspath ${BORINGSSL_LIB}) -lcrypto" go test "${BRON_CRYPTO_HOME}/..."

.PHONY: test-race
test-race: build-boringssl
	CGO_CFLAGS="-I$(abspath ${BORINGSSL_INCLUDE})" CGO_LDFLAGS="-L$(abspath ${BORINGSSL_LIB}) -lcrypto" go test -race "${BRON_CRYPTO_HOME}/..."

.PHONY: bench
bench: build-boringssl
	CGO_CFLAGS="-I$(abspath ${BORINGSSL_INCLUDE})" CGO_LDFLAGS="-L$(abspath ${BORINGSSL_LIB}) -lcrypto" go test "${BRON_CRYPTO_HOME}/..." -bench=. -run=^$

.PHONY: coverage
coverage: build-boringssl
	CGO_CFLAGS="-I$(abspath ${BORINGSSL_INCLUDE})" CGO_LDFLAGS="-L$(abspath ${BORINGSSL_LIB}) -lcrypto" go test "${BRON_CRYPTO_HOME}/..." -coverprofile=coverage.out

.PHONY: lint
lint: build-boringssl
	CGO_CFLAGS="-I$(abspath ${BORINGSSL_INCLUDE})" CGO_LDFLAGS="-L$(abspath ${BORINGSSL_LIB}) -lcrypto" golangci-lint run "${BRON_CRYPTO_HOME}/..."

.PHONY: lint-fix
lint-fix: build-boringssl
	CGO_CFLAGS="-I$(abspath ${BORINGSSL_INCLUDE})" CGO_LDFLAGS="-L$(abspath ${BORINGSSL_LIB}) -lcrypto" golangci-lint run "${BRON_CRYPTO_HOME}/..." --fix

.PHONY: clean
clean:
	go clean -cache
	rm -rf "${BORINGSSL_HOME}"

