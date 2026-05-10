BRON_CRYPTO_HOME := $(dir $(lastword $(MAKEFILE_LIST)))
BORINGSSL_URL := https://github.com/google/boringssl
BORINGSSL_COMMIT := 79048f1f1d8e6b7f9ca59b95c24486c8149122a4
BORINGSSL_HOME := ${BRON_CRYPTO_HOME}/thirdparty/boringssl/
BORINGSSL_INCLUDE := ${BORINGSSL_HOME}/include
BORINGSSL_LIB := ${BORINGSSL_HOME}/${BUILD_PREFIX}build/
GOVULNCHECK := go run golang.org/x/vuln/cmd/govulncheck@v1.3.0

.PHONY: all
all: build sbom

.PHONY: sbom
sbom:
	go list -m -json all > sbom.modules.json

${BORINGSSL_INCLUDE}/openssl:
	git clone --filter=blob:none --no-checkout "${BORINGSSL_URL}" "${BORINGSSL_HOME}"
	git -C "${BORINGSSL_HOME}" fetch --depth 1 origin "${BORINGSSL_COMMIT}"
	git -C "${BORINGSSL_HOME}" checkout --detach "${BORINGSSL_COMMIT}"
	test "$$(git -C "${BORINGSSL_HOME}" rev-parse HEAD)" = "${BORINGSSL_COMMIT}"

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

.PHONY: govulncheck
govulncheck: build-boringssl
	CGO_CFLAGS="-I$(abspath ${BORINGSSL_INCLUDE})" CGO_LDFLAGS="-L$(abspath ${BORINGSSL_LIB}) -lcrypto" $(GOVULNCHECK) "${BRON_CRYPTO_HOME}/..."

.PHONY: ct-check
ct-check:
	"${BRON_CRYPTO_HOME}/scripts/ci/ct-check.sh"

.PHONY: workflow-policy-check
workflow-policy-check:
	"${BRON_CRYPTO_HOME}/scripts/ci/verify-workflows.sh"

.PHONY: boringssl-pin-check
boringssl-pin-check:
	"${BRON_CRYPTO_HOME}/scripts/ci/verify-boringssl-pin.sh"

.PHONY: unsafe-api-check
unsafe-api-check:
	"${BRON_CRYPTO_HOME}/scripts/ci/unsafe-api-check.sh"

.PHONY: fuzz-smoke
fuzz-smoke: build-boringssl
	CGO_CFLAGS="-I$(abspath ${BORINGSSL_INCLUDE})" CGO_LDFLAGS="-L$(abspath ${BORINGSSL_LIB}) -lcrypto" go test "${BRON_CRYPTO_HOME}/pkg/base/serde/..." "${BRON_CRYPTO_HOME}/pkg/network/..."

.PHONY: security
security: ct-check workflow-policy-check boringssl-pin-check unsafe-api-check govulncheck

.PHONY: clean
clean:
	go clean -cache
	rm -rf "${BORINGSSL_HOME}"
