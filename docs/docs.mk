# VERBOSE:="--verbose"

.PHONY: docs
docs: spec all-standalone-docs

.PHONY: deps-docs
deps-docs:
	python3 -m pip install -r docs/requirements.txt

.PHONY: spec
spec:
	python3 docs/build.py $(VERBOSE) --main

.PHONY: standalone-docs
standalone-docs:
	python3 docs/build.py --clean $(VERBOSE) --standalone-path "$(BRON_PKG)"

.PHONY: all-standalone-docs
all-standalone-docs:
	python3 docs/build.py --clean $(VERBOSE) --standalone-path "all"

.PHONY: clean-docs
clean-docs:
	python3 docs/build.py --clean
