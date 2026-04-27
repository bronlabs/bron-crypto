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
5. Before writing the report, actively check the categories below — these are the ones most often missed when the diff is large:
    - **Sampler/verifier distribution parity**: do honest and adversarial paths produce values from the same distribution? (e.g., equivocated witness range vs. honest sampler range, decoded vs. constructed values)
    - **Wire-format-affecting changes**: transcript labels, CBOR tags/field names, hash domain separators, error message text used as protocol identifiers, generator-derivation inputs. These break interop silently.
    - **Lost coverage**: when test files are renamed/deleted, did benchmarks or edge-case tests get replaced or just dropped? Diff `-` lines in `_test.go` files for assertions with no replacement.
    - **Stale identifiers after renames**: test function names, `testdata/rapid/*` directory names, doc comments referencing the old method, error messages echoing the old name.
    - **Generic-instantiation runtime panics**: `StructureMustBeAs` / type assertions on code paths that a new flavor exercises. Type-level smoke-test assertions don't catch runtime panics.
    - **Constructor-vs-deserializer parity**: do `Unmarshal*` / `From*` methods re-run the same invariants the `New*` constructors enforce? Trust-boundary code must validate.
    - **Doc-vs-code drift**: doc comments that survived a behavioral change unchanged ("rejects zero" when the zero check was removed; "prime group" when the type changed to a more general one).
    - **Cryptographic semantics, not just mechanics**: for each new public function, reason about what an adversary controls, what's secret, and where the security reduction lives. Mechanical checks (errs.Wrap, doc comments) are necessary but not sufficient.
6. Output as GitHub-flavoured markdown. Use headers, **bold** severity tags, and `code` spans for paths so the terminal renders a clear visual hierarchy. Do not wrap the whole report in a fenced code block (that defeats the renderer). Template:

    ```
    ## PR #<N> — <title>

    **Audit-scope files:** `path1`, `path2` _(or "none")_

    ### Findings

    - **[blocker]** `file.go:42` — short description
    - **[nit]** `file.go:99` — short description
    - **[question]** `file.go:123` — short description

    _(If none: "No findings.")_

    ### Description vs. diff

    <one line: "matches" or the specific mismatch>

    ### Recommendation

    <one short paragraph>
    ```

    Severity tags must be one of `[blocker]`, `[nit]`, `[question]` and always bolded so they pop in the terminal. Order findings as you discover them; severity tags are for the reader, not a filing system. Aim for breadth of investigation before brevity — a thorough report with ungrouped findings beats a tidy one with gaps.

## Don'ts
- Don't post the review; just print it. The user will paste / edit.
- Don't restate the PR title or summary; assume the user can read.
- Don't suggest cleanup beyond the diff unless it's a real correctness issue.
