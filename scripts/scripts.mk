.PHONY: test-package-%
test-package-%:
	${RUN_IN_CLAUSE} 'make clean'
	${RUN_IN_CLAUSE} 'make unit-test-long-${*}'
	${RUN_IN_CLAUSE} 'make fuzz-test-${*}'
	${RUN_IN_CLAUSE} 'make deflake-test-${*}'

.PHONY: fuzz-test-%
fuzz-test-%:
	${RUN_IN_CLAUSE} 'make clean'
	${RUN_IN_CLAUSE} 'chmod +x ${SCRIPTS_DIR}/run_fuzz.sh'
	${RUN_IN_CLAUSE} '${SCRIPTS_DIR}/run_fuzz.sh ${*} --fuzztime=10s'

.PHONY: long-fuzz-test-%
long-fuzz-test-%:
	${RUN_IN_CLAUSE} 'make clean'
	${RUN_IN_CLAUSE} 'chmod +x ${SCRIPTS_DIR}/run_fuzz.sh'
	${RUN_IN_CLAUSE} '${SCRIPTS_DIR}/run_fuzz.sh ${*} --fuzztime=120s'

.PHONY: profile-test-%
profile-test-%:
	${RUN_IN_CLAUSE} 'make clean'
	${RUN_IN_CLAUSE} 'chmod +x ${SCRIPTS_DIR}/run_profile.sh'
	${RUN_IN_CLAUSE} '${SCRIPTS_DIR}/run_profile.sh ${*}'

.PHONY: benchmark-test-%
benchmark-test-%:
	${RUN_IN_CLAUSE} 'make clean'
	${RUN_IN_CLAUSE} 'chmod +x ${SCRIPTS_DIR}/run_benchmark.sh'
	${RUN_IN_CLAUSE} '${SCRIPTS_DIR}/run_benchmark.sh ${*}'

.PHONY: cte-test-%
cte-test-%:
	${RUN_IN_CLAUSE} 'make clean'
	${RUN_IN_CLAUSE} 'chmod +x ${SCRIPTS_DIR}/run_cte.sh'
	${RUN_IN_CLAUSE} '${SCRIPTS_DIR}/run_cte.sh ${*}'

.PHONY: unit-test-%
unit-test-%:
	${RUN_IN_CLAUSE} 'make clean'
	${RUN_IN_CLAUSE} 'chmod +x ${SCRIPTS_DIR}/run_unittest.sh'
	${RUN_IN_CLAUSE} '${SCRIPTS_DIR}/run_unittest.sh ${*} -short'

.PHONY: long-unit-test-%
long-unit-test-%:
	${RUN_IN_CLAUSE} 'make clean'
	${RUN_IN_CLAUSE} 'chmod +x ${SCRIPTS_DIR}/run_unittest.sh'
	${RUN_IN_CLAUSE} '${SCRIPTS_DIR}/run_unittest.sh ${*}'

.PHONY: deflake-test-%
deflake-test-%:
	${RUN_IN_CLAUSE} 'make clean'
	${RUN_IN_CLAUSE} 'chmod +x ${SCRIPTS_DIR}/run_deflake.sh'
	${RUN_IN_CLAUSE} '${SCRIPTS_DIR}/run_deflake.sh ${*}'

.PHONY: long-deflake-test-%
long-deflake-test-%:
	${RUN_IN_CLAUSE} 'make clean'
	${RUN_IN_CLAUSE} 'chmod +x ${SCRIPTS_DIR}/run_deflake.sh'
	${RUN_IN_CLAUSE} '${SCRIPTS_DIR}/run_deflake.sh ${*} -short'

.PHONY: test-master
test-master:
	${RUN_IN_CLAUSE} 'make test-long'
	${RUN_IN_CLAUSE} 'make lint-long'
	${RUN_IN_CLAUSE} 'make fuzz'
	${RUN_IN_CLAUSE} 'make deflake'

.PHONY: test-nightly
test-nightly:
	${RUN_IN_CLAUSE} 'make test-long'
	${RUN_IN_CLAUSE} 'make lint-long'
	${RUN_IN_CLAUSE} 'make fuzz-long'
	${RUN_IN_CLAUSE} 'make deflake-long'
	# TODO: enable this later
	# ${RUN_IN_CLAUSE} 'make sync-thirdparty'
