.PHONY: all build bench clean cover deflake fmt lint test test-clean test-long

GOENV=GO111MODULE=on
GO=${GOENV} go

COVERAGE_OUT=/tmp/coverage.out
PACKAGE=./...

TEST_CLAUSE= $(if ${TEST}, -run ${TEST})

DOCTOOLS=docker run --rm  -v "$$(pwd)":"$$(pwd)" -w "$$(pwd)" doctools:latest

.PHONY: all
all: githooks test build lint fmt deps docs

.PHONY: build
build:
	${GO} build ./...

.PHONY: bench
bench:
	${GO} test -short -bench=. -test.timeout=0 -run=^noTests ./...

.PHONY: clean
clean:
	${GO} clean -cache -modcache -i -r

.PHONY: cover
cover: ## compute and display test coverage report
	${GO} test -short -coverprofile=${COVERAGE_OUT} ${PACKAGE}
	${GO} tool cover -html=${COVERAGE_OUT}

.PHONY: deps
deps: ## Build dockerized autodoc tools
	@docker build -t doctools:latest .

.PHONY: docs
docs: ## Apply copyright headers and re-build package-level documents
	@${DOCTOOLS} spdx

gen-readme-docs:
	@${DOCTOOLS} gomarkdoc --output '{{.Dir}}/README.md' ./...

.PHONY: fmt
fmt:
	${GO} fmt ./...

.PHONY: githooks
githooks:
	git config core.hooksPath .githooks
	chmod +x .githooks/*

.PHONY: lint
lint:
	${GO} vet ./...
	golangci-lint run

.PHONY: lint-fix
lint-fix:
	${GO} vet ./...
	golangci-lint run --fix

.PHONY: deflake
deflake: ## Runs tests many times to detect flakes
	${GO} test -count=1000 -short -timeout 0 ${TEST_CLAUSE} ./...

.PHONY: test
test:
	${GO} test -short ${TEST_CLAUSE} ./...

.PHONY: test-clean
test-clean: ## Clear test cache and force all tests to be rerun
	${GO} clean -testcache && ${GO} test -count=1 -short ${TEST_CLAUSE} ./...

.PHONY: test-long
test-long: ## Runs all tests, including long-running tests
	${GO} test ${TEST_CLAUSE} ./...

.PHONY: test-clean-long
test-clean-long: ## Clear test cache and force all tests to be rerun
	${GO} clean -testcache && ${GO} test -count=1 ${TEST_CLAUSE} ./...

.PHONY: fuzz-test
fuzz-test: ## build and run fuzz test
	go test github.com/copperexchange/krypton/pkg/signatures/threshold/tschnorr/frost/fuzz \
		-fuzz ^FuzzInteractiveSigning$$ \
		-parallel=10 \
		-fuzztime=120s
	go test github.com/copperexchange/krypton/pkg/signatures/threshold/tschnorr/frost/fuzz \
		-fuzz ^FuzzNonInteractiveSigning$$ \
		-parallel=10 \
		-fuzztime=120s
	go test github.com/copperexchange/krypton/pkg/signatures/threshold/tschnorr/lindell22/fuzz \
		-fuzz ^FuzzInteractiveSigning$$ \
		-parallel=10 \
		-fuzztime=120s
	go test github.com/copperexchange/krypton/pkg/signatures/threshold/tschnorr/lindell22/fuzz \
		-fuzz ^FuzzNonInteractiveSigning$$ \
		-parallel=10 \
		-fuzztime=120s
	go test github.com/copperexchange/krypton/pkg/signatures/threshold/tecdsa/lindell17/fuzz \
		-fuzz ^FuzzInteractiveSigning$$ \
		-parallel=10 \
		-fuzztime=120s
	go test github.com/copperexchange/krypton/pkg/signatures/threshold/tecdsa/lindell17/fuzz \
		-fuzz ^FuzzNonInteractiveSigning$$ \
		-parallel=10 \
		-fuzztime=120s
	go test github.com/copperexchange/krypton/pkg/signatures/threshold/tecdsa/dkls23/fuzz \
		-fuzz ^FuzzInteractiveSigning$$ \
		-parallel=10 \
		-fuzztime=120s


.PHONY: run-profile-frost-dkg
run-profile-frost-dkg:
	PROFILE_T=2 PROFILE_N=3 go test -timeout 300s -run ^TestRunProfile$$ github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tschnorr/frost/keygen/dkg -memprofile ${TMPDIR}dkg_memprofile_K256.out -cpuprofile ${TMPDIR}dkg_cpuprofile_K256.out
	go tool pprof -top ${TMPDIR}dkg_cpuprofile_K256.out | grep copperexchange
	go tool pprof -top ${TMPDIR}dkg_memprofile_K256.out | grep copperexchange
	PROFILE_T=2 PROFILE_N=3 PROFILE_CURVE=ED25519 PROFILE_HASH=SHA3 go test -timeout 300s -run ^TestRunProfile$$ github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tschnorr/frost/keygen/dkg -memprofile ${TMPDIR}dkg_memprofile_ED25519.out -cpuprofile ${TMPDIR}dkg_cpuprofile_ED25519.out
	go tool pprof -top ${TMPDIR}dkg_cpuprofile_ED25519.out | grep copperexchange
	go tool pprof -top ${TMPDIR}dkg_memprofile_ED25519.out | grep copperexchange

.PHONY: run-profile-frost-interactive-signing
run-profile-frost-interactive-signing:
	PROFILE_T=2 PROFILE_N=3 go test -timeout 300s -run ^TestRunProfile$$ github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tschnorr/frost/signing/interactive -memprofile ${TMPDIR}interactive_memprofile_K256.out -cpuprofile ${TMPDIR}interactive_cpuprofile_K256.out
	go tool pprof -top ${TMPDIR}interactive_cpuprofile_K256.out | grep copperexchange
	go tool pprof -top ${TMPDIR}interactive_memprofile_K256.out | grep copperexchange
	PROFILE_T=2 PROFILE_N=3 PROFILE_CURVE=ED25519 PROFILE_HASH=SHA3 go test -timeout 300s -run ^TestRunProfile$$ github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tschnorr/frost/signing/interactive -memprofile ${TMPDIR}interactive_memprofile_ED25519.out -cpuprofile ${TMPDIR}interactive_cpuprofile_ED25519.out
	go tool pprof -top ${TMPDIR}interactive_cpuprofile_ED25519.out | grep copperexchange
	go tool pprof -top ${TMPDIR}interactive_memprofile_ED25519.out | grep copperexchange

.PHONY: run-profile-frost-noninteractive-signing
run-profile-frost-noninteractive-signing:
	PROFILE_T=2 PROFILE_N=3 go test -timeout 300s -run ^TestRunProfile$$ github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tschnorr/frost/signing/noninteractive -memprofile ${TMPDIR}noninteractive_memprofile_K256.out -cpuprofile ${TMPDIR}noninteractive_cpuprofile_K256.out
	go tool pprof -top ${TMPDIR}noninteractive_cpuprofile_K256.out | grep copperexchange
	go tool pprof -top ${TMPDIR}noninteractive_memprofile_K256.out | grep copperexchange
	PROFILE_T=2 PROFILE_N=3 PROFILE_CURVE=ED25519 PROFILE_HASH=SHA3 go test -timeout 300s -run ^TestRunProfile$$ github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tschnorr/frost/signing/noninteractive -memprofile ${TMPDIR}noninteractive_memprofile_ED25519.out -cpuprofile ${TMPDIR}noninteractive_cpuprofile_ED25519.out
	go tool pprof -top ${TMPDIR}noninteractive_cpuprofile_ED25519.out | grep copperexchange
	go tool pprof -top ${TMPDIR}noninteractive_memprofile_ED25519.out | grep copperexchange

.PHONY: run-time-tests
run-time-tests:
	go clean -testcache
	EXEC_TIME_TEST=1 go test -timeout 600s -run ^Test_MeasureConstantTime ./...
