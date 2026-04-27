# AGENTS.md

Behavioral guidelines to reduce common LLM coding mistakes. Merge with project-specific instructions as needed.

**Tradeoff:** These guidelines bias toward caution over speed. For trivial tasks, use judgment.

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:

- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:

- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:

- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:

- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:

```pseudocode
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

## 5. Project-Specific Guidelines

### Read first

- `./DEVELOPMENT.md` — build / boringssl / docker
- `./TESTING.md` — test types, CGO flags for `go test`
- `./CONTRIBUTING.md` — PR flow
- `./SECURITY.md` — security policy and disclosure

### Quick commands

- `make build` / `make test` / `make test-race` / `make lint` / `make bench`
- `make lint-fix` to auto-fix gofumpt/gci
- `./run-in-docker.sh make <target>` for a clean toolchain
- CI runs with `GODEBUG=cpu.avx2=off` (self-hosted runner)

### Errors

- Use `errs-go`. Always `errs.Wrap(err).WithMessage("…")`; never return bare errors.
- One `errors.go` per package with sentinel `Err…` values; comment each.
- For cross-package shared sentinels, see `pkg/signatures/errors.go` for the canonical pattern. Don't introduce duplicates without aliasing.
- Identifiable abort either uses `pkg/base/errors.go` (`ErrAbort`, tag-based culprit IDs), OR it attaches `base.IdentifiableAbortPartyIDTag` using `WithTag` method.

### Conventions

- Per-package layout: `doc.go`, `errors.go`, then one file per concept (`scheme.go`, `committer.go`, `verifier.go`, …). Tests as siblings.
- Test file suffixes: `_test.go` (unit), `_prop_test.go` (rapid property), `_smoke_test.go` (fast end-to-end).
- Imports follow gci order from `.golangci.yml`. Run `make lint-fix` rather than fight it.
- Spelling: pick one variant per file; British is common ("serialisation", "flavour"). Don't mix the symbol and message text (e.g., `ErrSerialization = errs.New("serialisation error")` is a smell).
- All exported types/functions/methods need doc comments. Range checks, secret-handling, and side-channel notes belong in the comments, not external docs.
- If there exist a constructor for a struct and one of its return types is an error, then it must be used everywhere except possibly in the tests, instead of manually initializing the struct.
- Formal documentation: Some package's README.md files contain a **Reference** heading. The paper they are citing may be found in `.docs/` directory within that package. Read that. Warn if the `.docs/` directory is empty.

### Crypto-specific guardrails

- Input validation in constructors, like range checks, are **not optional** — they often anchor a security reduction.
- Deserialization (`UnmarshalCBOR`, custom decoders) MUST sanitize and validate; treat them as a trust boundary.
- Trapdoor / secret types must say so in their doc comment.
- PRNG sources are explicit (`io.Reader` parameters); never default to `crypto/rand` silently inside helpers.
- If the code is designed to be constant time, then don't introduce timing-dependent branches without documentation.

### When you must not

- `--no-verify`, skipping hooks, weakening lint config, deleting tests to make CI pass.
- Force-pushing to `master`.
- Bumping BoringSSL or any audited dep in a feature PR; do it in its own PR.

---

**These guidelines are working if:** fewer unnecessary changes in diffs, fewer rewrites due to overcomplication, and clarifying questions come before implementation rather than after mistakes.
