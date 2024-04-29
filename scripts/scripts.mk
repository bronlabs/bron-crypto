SCRIPTS_DIR := $(dir $(lastword $(MAKEFILE_LIST)))

.PHONY: deps-linter
deps-linter:
	chmod +x ${SCRIPTS_DIR}/install_deps.sh
	${SCRIPTS_DIR}/install_deps.sh golangci-lint
	${SCRIPTS_DIR}/install_deps.sh nancy

.PHONY: test-package-%
test-package-%:
	$(MAKE) clean
	$(MAKE) unit-test-long-${*}
	$(MAKE) fuzz-test-${*}
	$(MAKE) deflake-test-${*}

.PHONY: fuzz-test-%
fuzz-test-%:
	$(MAKE) clean
	chmod +x ${SCRIPTS_DIR}/run_fuzz.sh
	${SCRIPTS_DIR}/run_fuzz.sh ${*} --fuzztime=10s

.PHONY: long-fuzz-test-%
long-fuzz-test-%:
	$(MAKE) clean
	chmod +x ${SCRIPTS_DIR}/run_fuzz.sh
	${SCRIPTS_DIR}/run_fuzz.sh ${*} --fuzztime=120s

.PHONY: profile-test-%
profile-test-%:
	$(MAKE) clean
	chmod +x ${SCRIPTS_DIR}/run_profile.sh
	${SCRIPTS_DIR}/run_profile.sh ${*}

.PHONY: benchmark-test-%
benchmark-test-%:
	$(MAKE) clean
	chmod +x ${SCRIPTS_DIR}/run_benchmark.sh
	${SCRIPTS_DIR}/run_benchmark.sh ${*}

.PHONY: cte-test-%
cte-test-%:
	$(MAKE) clean
	chmod +x ${SCRIPTS_DIR}/run_cte.sh
	${SCRIPTS_DIR}/run_cte.sh ${*}

.PHONY: unit-test-%
unit-test-%:
	$(MAKE) clean
	chmod +x ${SCRIPTS_DIR}/run_unittest.sh
	${SCRIPTS_DIR}/run_unittest.sh ${*} -short

.PHONY: long-unit-test-%
long-unit-test-%:
	$(MAKE) clean
	chmod +x ${SCRIPTS_DIR}/run_unittest.sh
	${SCRIPTS_DIR}/run_unittest.sh ${*}

.PHONY: deflake-test-%
deflake-test-%:
	$(MAKE) clean
	chmod +x ${SCRIPTS_DIR}/run_deflake.sh
	${SCRIPTS_DIR}/run_deflake.sh ${*}

.PHONY: long-deflake-test-%
long-deflake-test-%:
	$(MAKE) clean
	chmod +x ${SCRIPTS_DIR}/run_deflake.sh
	${SCRIPTS_DIR}/run_deflake.sh ${*} -short

.PHONY: test-master
test-master:
	$(MAKE) test-long
	$(MAKE) lint-long
	$(MAKE) fuzz
	$(MAKE) deflake

.PHONY: test-nightly
test-nightly:
	$(MAKE) test-long
	$(MAKE) lint-long
	$(MAKE) fuzz-long
	$(MAKE) deflake-long
	$(MAKE) sync-thirdparty
