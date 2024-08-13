LINTER_IMAGE_NAME := "linter-image"

RUN_IN_DOCKER := docker run --user `id -u`:`id -g` --rm -it --platform=linux/arm64 -v ${KRYPTON_PRIMITIVES_HOME}:/usr/local/src -e GOLANGCI_LINT_CACHE=/usr/local/src/.golangcicache -e GOCACHE=/usr/local/src/.gocache ${LINTER_IMAGE_NAME} sh -c

.PHONY: check-deps lint-long-go lint-fix-go lint-short lint lint-long lint-fix build-image

check-deps: build-image
	$(RUN_IN_DOCKER) "go list -json -m all | nancy sleuth -d /tmp/.ossindexcache"

lint-long-go: build-image
	$(RUN_IN_DOCKER) "golangci-lint run --config=./.golangci-long.yml --timeout=120m"

lint-fix-go: build-image
	$(RUN_IN_DOCKER) "golangci-lint run --fix --config=./.golangci-long.yml --timeout=120m"

lint-short: build-image
	$(RUN_IN_DOCKER) 'golangci-lint run --fix --config=./.golangci-short.yml --timeout=120m'

lint: lint-short

lint-long: check-deps lint-long-go

lint-fix: check-deps lint-fix-go

build-image:
	docker build -f linter.Dockerfile -t $(LINTER_IMAGE_NAME) .
