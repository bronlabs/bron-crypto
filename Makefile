SELF_DIR := $(dir $(lastword $(MAKEFILE_LIST)))

# Determine the OS and set the PWD_CMD variable accordingly
ifeq ($(OS),Windows_NT)
    PWD_CMD = cd
else
    PWD_CMD = pwd
endif

KRYPTON_PRIMITIVES_HOME := $(shell cd ${SELF_DIR} && $(PWD_CMD))
KRYPTON_PRIMITIVES_SCRIPTS_DIR := $(KRYPTON_PRIMITIVES_HOME)/scripts
KRYPTON_PRIMITIVES_THIRD_PARTY_DIR := $(KRYPTON_PRIMITIVES_HOME)/thirdparty
KRYPTON_PRIMITIVES_DOCS_DIR := $(KRYPTON_PRIMITIVES_HOME)/docs

include $(KRYPTON_PRIMITIVES_HOME)/env.mk
include $(KRYPTON_PRIMITIVES_SCRIPTS_DIR)/scripts.mk
include $(KRYPTON_PRIMITIVES_THIRD_PARTY_DIR)/thirdparty.mk
include $(KRYPTON_PRIMITIVES_DOCS_DIR)/docs.mk

GOENV=GO111MODULE=on
GO=${GOENV} go

COVERAGE_OUT="$(mktemp -d)/coverage.out"

TEST_CLAUSE= $(if ${TEST}, -run ${TEST})
BUILD_TAGS= $(if ${TAGS}, -tags=${TAGS})

.PHONY: all
all: deps build lint test

pkg/base/errs/error_functions.gen.go:
pkg/base/errs/known_errors.gen.go:
	${GO} generate ./...
	golangci-lint run --fix ./pkg/base/errs

.PHONY: deps
deps: deps-go deps-boring

.PHONY: deps-go
deps-go:
	${GO} mod download
	${GO} mod verify
	${GO} mod tidy -compat=1.22

.PHONY: codegen
codegen: pkg/base/errs/error_functions.gen.go pkg/base/errs/known_errors.gen.go

.PHONY: build
build: codegen
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
	$(RUN_IN_DOCKER) 'GOLANGCI_LINT_CACHE=/usr/local/src/.golangcicache golangci-lint run --config=./.golangci-long.yml --timeout=120m'

.PHONY: lint-long
lint-long:
	@($(RUN_IN_DOCKER) 'go list -json -m all | nancy sleuth -d /tmp/.ossindexcache'\
	  $(RUN_IN_DOCKER) 'GOLANGCI_LINT_CACHE=/usr/local/src/.golangcicache golangci-lint run --fix --config=./.golangci-long.yml --timeout=120m') && wait

.PHONY: lint-fix
lint-fix:
	@($(RUN_IN_DOCKER) 'go list -json -m all | nancy sleuth -d /tmp/.ossindexcache'\
	  $(RUN_IN_DOCKER) 'GOLANGCI_LINT_CACHE=/usr/local/src/.golangcicache golangci-lint run --fix --config=./.golangci-long.yml --timeout=120m' \
	  $(RUN_IN_DOCKER) 'GOLANGCI_LINT_CACHE=/usr/local/src/.golangcicache golangci-lint run --fix --config=./.golangci-short.yml --timeout=120m') && wait

.PHONY: test
test:
	${GO} test ${BUILD_TAGS} -short ${TEST_CLAUSE} ./...

.PHONY: test-long
test-long: ## Runs all tests, including long-running tests
	${GO} test ${BUILD_TAGS} ${TEST_CLAUSE} -timeout 120m ./...

.PHONY: check-thirdparty
check-thirdparty:
	@${SCRIPTS_DIR}/check_thirdparty.sh ${THIRDPARTY_DIR}/manifest.txt

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