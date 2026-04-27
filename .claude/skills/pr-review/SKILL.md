---
name: pr-review
description: Review a GitHub PR by number against the repo's PR template, audit checklist, and conventions. Use when the user says "review PR #N" or "look at this PR".
effort: max
---

You are reviewing a PR for this repo. Be terse. Cite file:line. Don't approve or block — give findings.

## Steps

1. Get the PR: `gh pr view <N> --json title,body,files` and `gh pr diff <N>`.
2. Read the PR description against `.github/pull_request_template.md`. Note any unchecked box that the diff actually needed (tests claimed but absent, docs claimed but missing, etc.).
3. Walk the diff for:
    - **Description vs. diff drift**: claims of "backwards compatible" / "no API change" must match the diff.
    - **errs-go**: every new error path uses `errs.Wrap(err).WithMessage(...)`.
    - **Tests**: new public behavior has a `_test.go` change. New invariants → `_prop_test.go` with rapid. Reproducer for a bug fix. Ensure that the tests are meaningful and not just "coverage noise". For cryptography code, ensure the tests are cryptographically meaningful. If there are multiple ways to instantiate a test object, ensure that the tests cover them - for example, if a sharing scheme is defined over arbitrary monotone access structures, ensure that the tests cover at least two different access structures, not just the same one with different parameters.
    - **Documentation**: All exported types/functions/methods have doc comments - for cryptography code, they should be cryptographically meaningful. New packages must have a `doc.go` and a `README.md`. For existing packages, ensure that all documentation in `doc.go` and `README.md` still applies and are up to date after the change.
    - **Difficult to use/Gotchas**: Inform the user of any new API that looks easy to misuse, or any non-obvious invariants that aren't clearly documented.
    - **Naming/spelling consistency**: symbol + message text + doc comment in same variant (e.g. `ErrSerialization = errs.New("serialisation error")` is mixed; flag it).
    - **Generated code**: changes to `*.gen.go` should come with the matching generator change in `tools/`, or whereever they were generated in the first place.
    - **BoringSSL / audited deps**: bumps belong in their own PR.
4. Pre-existing issues: if the diff touches a file with pre-existing issues, note whether the diff makes them worse, better, or has no impact.
5. Output:
PR #:

    Audit-scope files: <list or "none">

    Findings
- file:line — short description — severity (blocker / nit / question)

    Description vs. diff: <one line if mismatch, otherwise "matches">

    Recommendation:

## Don'ts
- Don't post the review; just print it. The user will paste / edit.
- Don't restate the PR title or summary; assume the user can read.
- Don't suggest cleanup beyond the diff unless it's a real correctness issue.