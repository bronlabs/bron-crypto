# Contributing

Thanks for your interest in contributing to this project.

## Before you start

- By submitting a contribution, you agree that it will be licensed under the
  Apache 2.0 License (see `LICENSE`).
- For security issues, do not open public issues (see `SECURITY.md`).

## Getting set up

- Follow the development setup in `README.md`.
- BoringSSL is required for CGO builds; the Makefile handles this via
  `make build-boringssl`.

## Development workflow

1. Create a branch.
2. Make focused, incremental changes.
3. Add or update tests when relevant.
4. Run the relevant checks locally:

```bash
make test
make lint
```

Optional (but encouraged):

```bash
make bench
make coverage
```

## Code generation

If you modify files that use `//go:generate`, regenerate code where relevant:

```bash
make generate
```

Some generators use Docker (see `README.md` for details).

## Pull request guidelines

- Keep PRs small and focused.
- Include a clear description of the change and motivation (use PR template checklist for inspiration).
- Link related issues if applicable.
- Ensure tests pass.

## Code style

- Prefer explicit, readable code over cleverness.
- Keep exported APIs documented.
- Ensure lint checks pass.
