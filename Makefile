include scripts/Makefile

GOENV=GO111MODULE=on
GO=${GOENV} go

COVERAGE_OUT=/tmp/coverage.out
SCRIPTS_DIR=./scripts

TEST_CLAUSE= $(if ${TEST}, -run ${TEST})

.PHONY: all
all: build lint test

.PHONY: codegen
codegen:
	${GO} generate ./...
	golangci-lint run --fix ./pkg/base/errs

.PHONY: build
build:
	$(MAKE) codegen
	${GO} build ./...

.PHONY: bench
bench:
	${GO} test -short -bench=. -test.timeout=0 -run=^noTests ./...

.PHONY: clean
clean:
	${GO} clean -cache -modcache -r -i

.PHONY: clean-test
clean-test:
	${GO} clean -testcache

.PHONY: clean-fuzz
clean-fuzz:
	find . -type d -path "*/testdata" -exec rm -r -i {}/fuzz \;

.PHONY: cover
cover: ## compute and display test coverage report
	${GO} test -short -coverprofile=${COVERAGE_OUT} ./...
	${GO} tool cover -html=${COVERAGE_OUT}

.PHONY: githooks
githooks:
	git config core.hooksPath .githooks
	chmod +x .githooks/*

.PHONY: lint
lint:
	${GO} vet ./...
	golangci-lint run --timeout=5m

.PHONY: lint-long
lint-long:
	${GO} vet ./...
	golangci-lint run --timeout=120m

.PHONY: lint-fix
lint-fix:
	${GO} vet ./...
	${GO} fmt ./...
	golangci-lint run --fix --timeout=120m

.PHONY: test
test:
	${GO} test -short ${TEST_CLAUSE} ./...

.PHONY: prng-test
prng-test:
	CGO_ENABLED=1 ${GO} run main.go

.PHONY: test-long
test-long: ## Runs all tests, including long-running tests
	${GO} test ${TEST_CLAUSE} -timeout 120m ./...

.PHONY: check-aes
check-aes:
	chmod +x ${SCRIPTS_DIR}/check_aes.sh
	${SCRIPTS_DIR}/check_aes.sh

.PHONY: deflake
deflake: ## Runs short tests many times to detect flakes
	DEFLAKE_TIME_TEST=1 ${GO} test -count=100 -short -timeout 0 ${TEST_CLAUSE} ./...

.PHONY: deflake-long
deflake-long: ## Runs tests many times to detect flakes
	DEFLAKE_TIME_TEST=1 ${GO} test -count=50 -timeout 0 ${TEST_CLAUSE} ./...

.PHONY: fuzz
fuzz:
	$(MAKE) fuzz-test-pkg

.PHONY: fuzz-long
fuzz-long:
	$(MAKE) long-fuzz-test-pkg

