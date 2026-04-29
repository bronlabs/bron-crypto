---
name: audit
description: Audit a file, package, or diff for cryptographic correctness, errs-go compliance, deserialization safety, and audit-scope risk. Use when the user asks to audit, review for security, or check before merging into in-scope code.
effort: max
---

You are auditing crypto code. Be skeptical, cite line numbers, and don't fix things — report them.

## Steps

1. Identify the target (file, package, or PR/branch diff). Ask if unclear.
2. Determine scope: is the target reachable from `pkg/mpc/signatures/**` or transitively depended on by it? If yes, this is bug-bounty-eligible code (see SECURITY.md). The bug-bounty eligibility is for informational purposes only. Flag any correctness issues regardless of scope, but call out scope-reachability for risk assessment.
3. **Decide whether spec/paper compliance applies, then run it if so.** Spec-compliance is only meaningful when the target has a cited reference to compare against. Many packages don't (pure utilities like `pkg/base/utils/**`, generic data structures, glue code, ad-hoc helpers).
    - **Trigger spec-compliance if any of these are true** for the package:
        - `README.md` contains a `## References` heading or any `<!-- pdf[…]: -->` / `<!-- paper[…]: -->` / `<!-- spec[…]: -->` / `<!-- code[…]: -->` directive.
        - `README.md` cites a paper, RFC, BIP, SLIP, eprint link, DOI, conference proceeding, wiki page, or upstream source file/repo in prose.
        - The package has a `.docs/` directory, or any file under it.
        - A `doc.go` / inline code comment names a figure/algorithm/section ("Fig. 4 of KOS15", "RFC 9180 §4.1", "matches DecodeBase58").
        - The user explicitly asks for spec/paper compliance as part of the audit.
    - **Skip spec-compliance** if none of the above hold. Note in the report's `**Spec compliance:**` line that no reference is cited (`"n/a — no cited reference"`). Don't fabricate a comparison.
    - **When triggered, follow** `.claude/skills/spec-compliance/SKILL.md` against the target — including its reference-discovery rules (directives, `.docs/`, `docs/papers/`) and its kind-aware compliance walk (paper / spec / code). Spec-compliance is the canonical check for "does the code match its cited reference"; do not duplicate that work inline. Carry its findings into this audit per the severity mapping in step 5. If spec-compliance halts because a reference can't be resolved, surface that as an `[info]` blocker in the audit report and continue with the remaining checks below — don't paraphrase the missing reference.
    - **Borderline cases**: a package with a single named-but-uncited paper in prose ("Schnorr's protocol") and no directive is *applicable* — run spec-compliance, which will then ask for the PDF or fall back to README-as-informal-spec. A package that just imports a crypto primitive from another package without re-implementing anything is *not* applicable — its references live in the upstream package.
4. Walk the target for crypto-correctness issues *not* covered by spec-compliance:
    - **Inputs**: every exported entry point validates its arguments. Nil checks, range checks, group-membership / torsion-free / non-identity where appropriate. Flag any that look loose. (Spec-compliance flags missing checks the *reference* requires; this bullet flags loose validation that any reasonable crypto API should perform regardless.)
    - **Errors**: every error is wrapped with `errs.Wrap(err).WithMessage(...)`. No bare returns. Sentinels live in the package's or in one of the parent directories' `errors.go` and are documented. No silent fallbacks.
    - **Deserialization**: `UnmarshalCBOR` and any other decoder validate every field after parsing. Treat as a trust boundary. Cross-check that the validation in `Unmarshal` matches the constructor's `New…` validation — divergence is a vulnerability.
    - **Interactive Protocols**: if the package implements an interactive protocol, check that the messages (typically in `messages.go`) are serializable and immune against adversarial tampering.
    - **PRNG**: `io.Reader` is a parameter, not a package-level default. Failures from the PRNG are wrapped, not panicked.
5. **Fold spec-compliance findings into the audit report.** Translate spec-compliance severity tags into audit severity tags using the impact line each finding carries:
    - `[deviation vs. <ref>]` whose impact is soundness / ZK / correctness / extraction → `[critical]` (in-scope) or `[major]` (experimental).
    - `[deviation vs. <ref>]` whose impact is interop / round-trip only → `[major]`.
    - `[missing vs. <ref>]` of a security-relevant check → `[critical]` or `[major]` (same scoping rule).
    - `[missing vs. <ref>]` of a defensive / contract-clarity check → `[minor]`.
    - `[addition vs. <ref>]` that changes a distribution, leaks a bit, or alters a wire format → `[major]` or `[minor]` per impact.
    - `[addition vs. <ref>]` that is benign defensive code → `[info]`.
    - `[question vs. <ref>]` → `[info]` (note as "needs follow-up").
    - Acknowledged drift in the README → not a finding; mention once in the audit report's setup line.
    - Preserve the original reference attribution (`vs. <ref> §X`) in the finding text so the reader can trace back.
6. Output as GitHub-flavoured markdown. Use headers, **bold** severity tags, and `code` spans for paths. Don't wrap the whole report in a fenced code block. Template:

    ```
    ## Audit — <target>

    **Scope:** in-scope (reachable from `pkg/mpc/signatures/**`) — _or_ — experimental
    **Spec compliance:** <one-line verdict: "n/a — no cited reference" / "consistent — N questions" / "K deviations vs. <ref>" / "blocked — <ref> unresolved">

    ### Findings

    - **[critical]** `path:line` — finding (vs. `<ref>` §X if from spec-compliance)
      - _Fix:_ one-sentence suggestion
    - **[major]** `path:line` — finding
      - _Fix:_ ...
    - **[minor]** `path:line` — finding
      - _Fix:_ ...
    - **[info]** `path:line` — observation

    _(If none: "No findings.")_

    ### Summary

    **Counts:** N critical, N major, N minor, N info.
    **Highest-risk:** `path:line` — finding.
    ```

    Severity tags must be one of `[critical]`, `[major]`, `[minor]`, `[info]` and always bolded. Order findings by severity (critical first), then by file path.

## Don'ts
- Don't edit code.
- Don't assume "looks fine" — if you didn't read the relevant file, say so.
- Don't summarize the diff; the user can read it.
- Don't re-derive spec compliance inline. Run the `spec-compliance` skill and cite its findings; if you find yourself reading the paper/spec/reference yourself outside of that skill, you've drifted out of scope.
- Don't drop a spec-compliance finding because it doesn't fit cleanly into one of audit's four severity tags — pick the closest, attribute the original reference, and keep the impact one-liner.
