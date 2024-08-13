.PHONY: check-deps lint-long-go lint-long-go lint-short lint lint-long lint-fix

check-deps:
	go list -json -m all | nancy sleuth -d /tmp/.ossindexcache

lint-long-go:
	GOLANGCI_LINT_CACHE=/usr/local/src/.golangcicache golangci-lint run --config=./.golangci-long.yml --timeout=120m

lint-fix-go:
	GOLANGCI_LINT_CACHE=/usr/local/src/.golangcicache golangci-lint run --fix --config=./.golangci-long.yml --timeout=120m

lint-short: 
	GOLANGCI_LINT_CACHE=/usr/local/src/.golangcicache golangci-lint run --fix --config=./.golangci-short.yml --timeout=120m

lint: lint-short

lint-long: check-deps lint-long-go

lint-fix: check-deps lint-fix-go
