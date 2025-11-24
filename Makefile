BUILD_IMAGE_NAME := "docker.nobr.io/infra/golang:1.24-alpine"
SELF_DIR := $(dir $(lastword $(MAKEFILE_LIST)))

# Determine the OS and set the PWD_CMD variable accordingly
ifeq ($(OS),Windows_NT)
    PWD_CMD = cd
else
    PWD_CMD = pwd
endif

TESTS_FORMATTER := $(if ${HOST_EXECUTION_MODE},--junitfile build/junit-report/tests.xml,--format pkgname)
TESTCONTAINERS_ENV := $(if ${HOST_EXECUTION_MODE},TESTCONTAINERS_RYUK_DISABLED=true,)

HOST_EXECUTION_MODE := $(if ${LOCAL},true,${HOST_EXECUTION_MODE})
LOCAL_LINKER := $(if ${LOCAL}, -Xlinker -no_warn_duplicate_libraries)
# folder where project is located
PROJECT_DIR := $(shell cd ${SELF_DIR} && $(PWD_CMD))

# base folder of project. When we build inside docker, we should use /src as base folder
BASE_DIR := $(if ${HOST_EXECUTION_MODE},${PROJECT_DIR},/src)

SCRIPTS_DIR := $(BASE_DIR)/scripts
THIRD_PARTY_DIR := $(BASE_DIR)/thirdparty
DOCS_DIR := $(BASE_DIR)/docs

include ./scripts/scripts.mk
include ./thirdparty/thirdparty.mk
# include ./docs/docs.mk

GOENV=GO111MODULE=on CGO_CFLAGS="-I${BORINGSSL_DIR} -I${BORINGSSL_DIR}/include" CGO_LDFLAGS="-L${BORINGSSL_BUILD_DIR}/crypto -lcrypto ${LOCAL_LINKER}"
GO=${GOENV} go

BUILD_TAGS= $(if ${TAGS}, -tags=${TAGS})

# mount ssh to fetch deps, TESTCONTAINERS_HOST_OVERRIDE=host.docker.internal cause on macOS you need override https://github.com/testcontainers/testcontainers-java/blob/main/docs/supported_docker_environment/continuous_integration/dind_patterns.md#docker-only-example
RUN_IN_DOCKER := docker run --platform linux/amd64 --mount type=bind,src=/run/host-services/ssh-auth.sock,target=/run/host-services/ssh-auth.sock -e SSH_AUTH_SOCK="/run/host-services/ssh-auth.sock" -e TESTCONTAINERS_HOST_OVERRIDE=host.docker.internal --rm -it -v /tmp/.golangcicache:/tmp/.golangcicache -v /tmp/.gocache:/tmp/.gocache -v /tmp/.gomodcache:/tmp/.gomodcache -v /var/run/docker.sock:/var/run/docker.sock -v ${PROJECT_DIR}:/src ${BUILD_IMAGE_NAME} sh -c
RUN_ON_HOST := sh -c
RUN_IN_CLAUSE= $(if ${HOST_EXECUTION_MODE}, ${RUN_ON_HOST}, ${RUN_IN_DOCKER})

.PHONY: all deps deps-go deps-boring codegen build build-nocgo bench clean \
 clean-test clean-fuzz cover githooks test test-long check-thirdparty deflake \
 deflake-long fuzz fuzz-long check-deps lint-go lint lint-fix \

all: deps build lint test

pkg/base/constants.gen.go:
pkg/base/errs/error_functions.gen.go:
pkg/base/errs/known_errors.gen.go:
pkg/base/nt/millerrabin.gen.go:
	${RUN_IN_CLAUSE} '${GO} generate ./...'
	${RUN_IN_CLAUSE} 'golangci-lint run --fix ./pkg/base/errs'

local:
	LOCAL=true make ${cmd}

deps: deps-go deps-boring

deps-go:
	${RUN_IN_CLAUSE} '${GO} mod download'
	${RUN_IN_CLAUSE} '${GO} mod verify'
	${RUN_IN_CLAUSE} '${GO} mod tidy -compat=1.24'

codegen: pkg/base/constants.gen.go pkg/base/errs/error_functions.gen.go pkg/base/errs/known_errors.gen.go pkg/base/nt/millerrabin.gen.go

build: codegen
	${RUN_IN_CLAUSE} '${GO} build ./...'

build-nocgo: codegen
	${RUN_IN_CLAUSE} '${GO} build ${BUILD_TAGS} ./...'

bench:
	${RUN_IN_CLAUSE} '${GO} test -short -bench=. -test.timeout=0 -run=^noTests ./...'

clean:
	${RUN_IN_CLAUSE} '${GO} clean -cache -modcache -r -i'

clean-test:
	${RUN_IN_CLAUSE} '${GO} clean -testcache'

clean-fuzz:
	${RUN_IN_CLAUSE} 'find . -type d -path "*/testdata" -exec rm -r -i {}/fuzz \;'

cover: ## compute and display test coverage report
	${RUN_IN_CLAUSE} '${GO} test -short -coverprofile=${COVERAGE_OUT} ./...'
	${RUN_IN_CLAUSE} '${GO} tool cover -html=${COVERAGE_OUT}'

githooks:
	git config core.hooksPath .githooks
	chmod +x .githooks/*

test:
	${RUN_IN_CLAUSE} '${GOENV} go test -tags=${BUILD_TAGS} ./...'

test-edwards25519:
	${RUN_IN_CLAUSE} '${GOENV} go test -tags=${BUILD_TAGS} github.com/bronlabs/bron-crypto/tools/edwards25519-tester'

test-long: ## Runs all tests, including long-running tests
	${RUN_IN_CLAUSE} '${GOENV} go test -tags=${BUILD_TAGS} -timeout 120m ./...'
	${RUN_IN_CLAUSE} '${GOENV} go test -tags=${BUILD_TAGS} -timeout 120m github.com/bronlabs/bron-crypto/tools/edwards25519-tester'

check-thirdparty:
	@${SCRIPTS_DIR}/check_thirdparty.sh ${THIRDPARTY_DIR}/manifest.txt

deflake: ## Runs short tests many times to detect flakes
	${RUN_IN_CLAUSE} 'DEFLAKE_TIME_TEST=1 ${GO} test -tags=${BUILD_TAGS} -count=100 -short -timeout 0 ${TEST_CLAUSE} ./...'

deflake-long: ## Runs tests many times to detect flakes
	${RUN_IN_CLAUSE} 'DEFLAKE_TIME_TEST=1 ${GO} test -tags=${BUILD_TAGS} -count=50 -timeout 0 ${TEST_CLAUSE} ./...'

fuzz:
	${RUN_IN_CLAUSE} 'make fuzz-test-pkg'

fuzz-long:
	${RUN_IN_CLAUSE} 'make long-fuzz-test-pkg'

check-deps:
	# from: https://github.com/sonatype-nexus-community/nancy?tab=readme-ov-file#what-is-the-best-usage-of-nancy
	# takes into account only dependencies that will end-up in the final binary
	${RUN_IN_CLAUSE}  'go list -json -deps ./... | nancy sleuth --loud -d /tmp/.ossindexcache'

lint-go:
	${RUN_IN_CLAUSE} 'golangci-lint run --config=./.golangci.yml --timeout=120m'

lint-fix-go:
	${RUN_IN_CLAUSE} 'golangci-lint run --fix --config=./.golangci.yml --timeout=120m'

lint: check-deps lint-go

lint-fix: check-deps lint-fix-go
