---
name: audit
description: Audit a file, package, or diff for cryptographic correctness, errs-go compliance, deserialization safety, and audit-scope risk. Use when the user asks to audit, review for security, or check before merging into in-scope code.
effort: max
---

You are auditing crypto code. Be skeptical, cite line numbers, and don't fix things — report them.

## Steps

1. Identify the target (file, package, or PR/branch diff). Ask if unclear. 
2. Determine scope: is the target reachable from `pkg/mpc/signatures/**` or transitively depended on by it? If yes, this is bug-bounty-eligible code (see SECURITY.md). The bug-bounty eligibility is for informational purposes only. Flag any correctness issues regardless of scope, but call out scope-reachability for risk assessment.
3. Walk the target and check, in this order:
    - **Reductions / paper alignment**: if the package README cites a paper. Ensure that paper is in `$PKG/.docs/`. If it's not, inform the user. If it is, read it. Note any drift from the paper's specification or security assumptions. Note that the README might also have some information about drift or design decisions, so read it too.
    - **Inputs**: every exported entry point validates its arguments. Nil checks, range checks, group-membership / torsion-free / non-identity where appropriate. — flag any that look loose.
    - **Errors**: every error is wrapped with `errs.Wrap(err).WithMessage(...)`. No bare returns. Sentinels live in the package's or in one of the parent directories' `errors.go` and are documented. No silent fallbacks.
    - **Deserialization**: `UnmarshalCBOR` and any other decoder validate every field after parsing. Treat as a trust boundary. Cross-check that the validation in Unmarshal matches the constructor's `New…` validation — divergence is a vulnerability.
    - **Interactive Protocols**: if the package implements an interactive protocol, check that the messages (typically in `messages.go`) are serializable and immune against adversarial tampering.
    - **PRNG**: `io.Reader` is a parameter, not a package-level default. Failures from the PRNG are wrapped, not panicked.
4. Output as GitHub-flavoured markdown. Use headers, **bold** severity tags, and `code` spans for paths. Don't wrap the whole report in a fenced code block. Template:

    ```
    ## Audit — <target>

    **Scope:** in-scope (reachable from `pkg/mpc/signatures/**`) — _or_ — experimental

    ### Findings

    - **[critical]** `path:line` — finding
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
