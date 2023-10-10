GOENV=GO111MODULE=on
GO=${GOENV} go

COVERAGE_OUT=/tmp/coverage.out
PACKAGE=./...

TEST_CLAUSE= $(if ${TEST}, -run ${TEST})

.PHONY: all
all: build lint fmt test

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
	${GO} test ${TEST_CLAUSE} -timeout 120m ./...

.PHONY: test-clean-long
test-clean-long: ## Clear test cache and force all tests to be rerun
	${GO} clean -testcache && ${GO} test -count=1 ${TEST_CLAUSE} ./...

.PHONY: short-test-package-%
short-test-package-%:
	$(MAKE) short-unit-test-${*}

.PHONY: test-package-%
test-package-%: ## for example `make test-package-hashing` to run all test under hashing package
	$(MAKE) fuzz-test-${*}
	$(MAKE) profile-test-${*}
	$(MAKE) benchmark-test-${*}
	$(MAKE) cte-test-${*}
	$(MAKE) unit-test-${*}
	$(MAKE) deflake-test-${*}

.PHONY: fuzz-test-%
fuzz-test-%:
	chmod +x scripts/run_fuzz.sh
	scripts/./run_fuzz.sh ${*}

.PHONY: profile-test-%
profile-test-%:
	chmod +x scripts/run_profile.sh
	scripts/./run_profile.sh ${*}

.PHONY: benchmark-test-%
benchmark-test-%:
	chmod +x scripts/run_benchmark.sh
	scripts/./run_benchmark.sh ${*}

.PHONY: cte-test-%
cte-test-%:
	chmod +x scripts/run_cte.sh
	scripts/./run_cte.sh ${*}

.PHONY: unittest-test-%
unit-test-%:
	chmod +x scripts/run_unittest.sh
	scripts/./run_unittest.sh ${*}

.PHONY: short-unittest-test-%
short-unit-test-%:
	chmod +x scripts/run_unittest.sh
	scripts/./run_unittest.sh ${*} -test.short

.PHONY: deflake-test-%
deflake-test-%:
	chmod +x scripts/run_deflake.sh
	scripts/./run_deflake.sh ${*}

.PHONY: test-nightly
test-nightly:
	$(MAKE) test-package-pkg
