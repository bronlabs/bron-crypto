---
name: write-tests
description: Write tests (unit, property, or smoke) for a target file/function in this repo. Use when the user says "write tests for X" or "add tests".
effort: xhigh
---

You are adding tests in a crypto library. Tests must verify *correctness*, not just exercise the code path.

## Steps

1. Identify the target. Read it. Don't write tests for code you haven't read.
2. Decide test type(s):
    - **Unit** (`<x>_test.go`): exact-value checks, edge cases, error paths, table-driven where natural.
    - **Property** (`<x>_prop_test.go`): invariants under random inputs, using `pgregory.net/rapid`. Use this for any algebraic identity, round-trip (encode/decode, encrypt/decrypt, commit/verify), or cross-implementation equivalence.
    - **Smoke** (`<x>_smoke_test.go`): one fast end-to-end happy path, typically enforcing interface compliance. Optional unless the surface area is large.
    - **Bench** (`<x>_bench_test.go`): performance benchmarks.
3. Coverage matrix — at minimum, for each function:
    - zero / identity / one / -1 inputs
    - random inputs (cross-checked against a naive reference where possible)
    - error / range-violation paths return wrapped errors
    - cross-curve / cross-type for generic code (e.g. k256 *and* edwards25519 or testing various access structures for structures defined over arbitrary monotone ones)
4. Style:
    - `t.Run("subtest", func(t *testing.T) { … })` for organization.
    - Use `errs.Is(err, pkg.ErrInvalidArgument)` to assert wrapped errors, not string match.
    - Don't mock real crypto primitives. Use the smallest real instances available (e.g. tiny RSA modulus from a fixture, not a mock).
    - For property tests, write a clear invariant docstring at the top of each `rapid.Check`.
5. Correctness:
    - Sometimes you cannot compare or check equality of two types using native operators eg. can't check equality of two `*k256.Point` with `==` because it would mean pointer equality. Use the relevant internal methods like `Equal(T)` and alike if present.
    - If the code has any identifiable aborts, write tests that trigger them. Malicious parties should be correctly identified, and honest parties should not be identified.
    - If the code has non-identifiable aborts (ie. `base/errors.go:ErrAbort`), write a test that triggers that abort.

6. CGO heads-up: most tests need BoringSSL. Run with the Makefile's CGO flags (see TESTING.md). When in doubt, run `make test` from repo root.
7. Output as GitHub-flavoured markdown. Use headers, **bold**, and `code` spans so the terminal renders a clear visual hierarchy. Show the new file content via the editing tools (Write/Edit), not by pasting it inside this report. Don't wrap the whole report in a fenced code block. Template:

    ```
    ## Tests for <target>

    **File:** `path/to/x_test.go`
    **Types:** unit, property, smoke _(whichever apply)_

    ### Test plan

    - `TestFoo` — exact-value checks for the happy path
    - `TestFoo_Errors` — wrapped-error assertions for each `New…` precondition
    - `TestFoo_Property` — invariant: <one-liner>
    - `TestFoo_Smoke` — interface compliance for `<scheme>`

    ### Run

    `go test <pkg>` → **PASS** (N tests, T) — _or_ — **FAIL**: `<one-line summary>`
    ```

    If any subtests fail, fix them or report the discrepancy — don't paper over with `t.Skip`. Quote the failing subtest name and the assertion that fired in the **FAIL** line.

## Don'ts

- Don't add tests that pass by tautology (`assert (x == x)`).
- Don't `t.Parallel()` on tests that share fixtures or read package-level state without checking.
- Don't disable a property test on flake; reproduce, shrink, and fix the underlying issue.
- Don't add a test file just to bump coverage.
