SELF_DIR := $(dir $(lastword $(MAKEFILE_LIST)))
include $(SELF_DIR)/scripts/Makefile
include $(SELF_DIR)/thirdparty/thirdparty.mk

GOENV=GO111MODULE=on
GO=${GOENV} go

COVERAGE_OUT="$(mktemp -d)/coverage.out"
SCRIPTS_DIR="$(SELF_DIR)/scripts"


TEST_CLAUSE= $(if ${TEST}, -run ${TEST})
BUILD_TAGS= $(if ${TAGS}, -tags=${TAGS})

.PHONY: all
all: build lint test

pkg/base/errs/error_functions.gen.go:
pkg/base/errs/known_errors.gen.go:
	${GO} generate ./...
	golangci-lint run --fix ./pkg/base/errs

.PHONY: codegen
codegen: pkg/base/errs/error_functions.gen.go pkg/base/errs/known_errors.gen.go

.PHONY: build
build: build-boring codegen
	${GO} build ./...

.PHONY: build-nocgo
build-nocgo: codegen
	${GO} build ${BUILD_TAGS} ./...

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
	golangci-lint run --timeout=5m

.PHONY: lint-long
lint-long:
	golangci-lint run --timeout=120m

.PHONY: lint-fix
lint-fix:
	golangci-lint run --fix --timeout=120m

.PHONY: test
test:
	${GO} test ${BUILD_TAGS} -short ${TEST_CLAUSE} ./...

.PHONY: test-long
test-long: ## Runs all tests, including long-running tests
	${GO} test ${BUILD_TAGS} ${TEST_CLAUSE} -timeout 120m ./...

.PHONY: sync-thirdparty
sync-thirdparty:
	chmod +x ${SCRIPTS_DIR}/sync_thirdparty.sh
	${SCRIPTS_DIR}/sync_thirdparty.sh

.PHONY: deflake
deflake: ## Runs short tests many times to detect flakes
	DEFLAKE_TIME_TEST=1 ${GO} test ${BUILD_TAGS} -count=100 -short -timeout 0 ${TEST_CLAUSE} ./...

.PHONY: deflake-long
deflake-long: ## Runs tests many times to detect flakes
	DEFLAKE_TIME_TEST=1 ${GO} test ${BUILD_TAGS} -count=50 -timeout 0 ${TEST_CLAUSE} ./...

.PHONY: fuzz
fuzz:
	$(MAKE) fuzz-test-pkg

.PHONY: fuzz-long
fuzz-long:
	$(MAKE) long-fuzz-test-pkg

