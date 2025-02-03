BUILD_IMAGE_NAME := "docker.boople.co/infra/golang:1.23-alpine3.20"
SELF_DIR := $(dir $(lastword $(MAKEFILE_LIST)))

# Determine the OS and set the PWD_CMD variable accordingly
ifeq ($(OS),Windows_NT)
    PWD_CMD = cd
else
    PWD_CMD = pwd
endif

RUN_IN_GOCD := $(if ${LOCAL},true,${RUN_IN_GOCD})
# folder where project is located
PROJECT_DIR := $(shell cd ${SELF_DIR} && $(PWD_CMD))

# base folder of project. When we build inside docker, we should use /src as base folder
BASE_DIR := $(if ${RUN_IN_GOCD},${PROJECT_DIR},/src)
SCRIPTS_DIR := $(BASE_DIR)/scripts
THIRD_PARTY_DIR := $(BASE_DIR)/thirdparty
DOCS_DIR := $(BASE_DIR)/docs
LOCAL_LINKER := $(if ${LOCAL}, -Xlinker -no_warn_duplicate_libraries)

include ./scripts/scripts.mk
include ./thirdparty/thirdparty.mk
include ./docs/docs.mk

GOENV=GO111MODULE=on CGO_CFLAGS="-I${BORINGSSL_SUBMODULE} -I${BORINGSSL_SUBMODULE}/include" CGO_LDFLAGS="-L${BORINGSSL_BUILD}/crypto -lcrypto ${LOCAL_LINKER}"
GO=${GOENV} go

COVERAGE_OUT="$(mktemp -d)/coverage.out"

TESTS_FORMATTER := $(if ${RUN_IN_GOCD},--junitfile build/junit-report/tests.xml,--format pkgname)
TESTCONTAINERS_ENV := $(if ${RUN_IN_GOCD},TESTCONTAINERS_RYUK_DISABLED=true,)
TEST_CLAUSE= $(if ${TEST}, -run ${TEST})
BUILD_TAGS= $(if ${TAGS}, -tags=${TAGS})

# mount ssh to fetch deps, TESTCONTAINERS_HOST_OVERRIDE=host.docker.internal cause on macOS you need override https://github.com/testcontainers/testcontainers-java/blob/main/docs/supported_docker_environment/continuous_integration/dind_patterns.md#docker-only-example
RUN_IN_DOCKER := docker run --mount type=bind,src=/run/host-services/ssh-auth.sock,target=/run/host-services/ssh-auth.sock -e SSH_AUTH_SOCK="/run/host-services/ssh-auth.sock" -e TESTCONTAINERS_HOST_OVERRIDE=host.docker.internal --rm -it -v /tmp/.golangcicache:/tmp/.golangcicache -v /tmp/.gocache:/tmp/.gocache -v /tmp/.gomodcache:/tmp/.gomodcache -v /var/run/docker.sock:/var/run/docker.sock -v ${PROJECT_DIR}:/src ${BUILD_IMAGE_NAME} sh -c
RUN_IN_CI := sh -c
RUN_IN_CLAUSE= $(if ${RUN_IN_GOCD}, ${RUN_IN_CI}, ${RUN_IN_DOCKER})

.PHONY: all deps deps-go deps-boring codegen build build-nocgo bench clean \
 clean-test clean-fuzz cover githooks test test-long lint lint-long check-thirdparty deflake \
 deflake-long fuzz fuzz-long check-deps lint-long-go lint-long-go lint-short lint lint-long lint-fix \

all: deps build lint test

pkg/base/errs/error_functions.gen.go:
pkg/base/errs/known_errors.gen.go:
	${RUN_IN_CLAUSE} '${GO} generate ./...'
	${RUN_IN_CLAUSE} 'golangci-lint run --fix ./pkg/base/errs'

local:
	LOCAL=true make ${cmd}

deps: deps-go deps-boring

deps-go:
	${RUN_IN_CLAUSE} '${GO} mod download'
	${RUN_IN_CLAUSE} '${GO} mod verify'
	${RUN_IN_CLAUSE} '${GO} mod tidy -compat=1.23'

codegen: pkg/base/errs/error_functions.gen.go pkg/base/errs/known_errors.gen.go

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
	${RUN_IN_CLAUSE} '${GOENV} gotestsum ${BUILD_TAGS} -- ./...'

test-edwards25519:
	${RUN_IN_CLAUSE} '${GOENV} gotestsum ${BUILD_TAGS} -- github.com/bronlabs/krypton-primitives/tools/edwards25519-tester'

test-long: ## Runs all tests, including long-running tests
	${RUN_IN_CLAUSE} '${GOENV} gotestsum ${BUILD_TAGS} -- -timeout 120m ./...'
	${RUN_IN_CLAUSE} '${GOENV} gotestsum ${BUILD_TAGS} -- -timeout 120m github.com/bronlabs/krypton-primitives/tools/edwards25519-tester'

check-thirdparty:
	@${SCRIPTS_DIR}/check_thirdparty.sh ${THIRDPARTY_DIR}/manifest.txt

deflake: ## Runs short tests many times to detect flakes
	${RUN_IN_CLAUSE} 'DEFLAKE_TIME_TEST=1 ${GO} test ${BUILD_TAGS} -count=100 -short -timeout 0 ${TEST_CLAUSE} ./...'

deflake-long: ## Runs tests many times to detect flakes
	${RUN_IN_CLAUSE} 'DEFLAKE_TIME_TEST=1 ${GO} test ${BUILD_TAGS} -count=50 -timeout 0 ${TEST_CLAUSE} ./...'

fuzz:
	${RUN_IN_CLAUSE} 'make fuzz-test-pkg'

fuzz-long:
	${RUN_IN_CLAUSE} 'make long-fuzz-test-pkg'

check-deps:
	# from: https://github.com/sonatype-nexus-community/nancy?tab=readme-ov-file#what-is-the-best-usage-of-nancy
	# takes into account only dependencies that will end-up in the final binary
	${RUN_IN_CLAUSE}  'go list -json -deps ./... | nancy sleuth --loud -d /tmp/.ossindexcache'

lint-long-go:
	${RUN_IN_CLAUSE} 'golangci-lint run --config=./.golangci-long.yml --timeout=120m'

lint-fix-go:
	${RUN_IN_CLAUSE} 'golangci-lint run --fix --config=./.golangci-long.yml --timeout=120m'

lint-short:
	${RUN_IN_CLAUSE} 'golangci-lint run --fix --config=./.golangci-short.yml --timeout=120m'

lint: lint-short

lint-long: check-deps lint-long-go

lint-fix: check-deps lint-fix-go
