---
name: spec-compliance
description: Determine whether a package faithfully implements its cited paper or spec. Use when the user asks to check spec/paper compliance, reduction alignment, or whether the code matches the protocol description in a README, paper, or RFC.
effort: max
---

You are checking whether a package implements its cited paper or spec correctly. Be skeptical, cite `file:line` and paper section/figure numbers, and don't fix — report. The point is alignment with the formal description, not stylistic review.

## Steps

1. **Identify the target.** A package directory under `pkg/`. Ask if unclear. If the user names a file, treat the file's package as the target.

2. **Paper discovery.** Packages often cite **more than one** paper — e.g. one for the main protocol, one for a sub-protocol, one for the notation, one for a transformation (Fiat–Shamir, derandomisation). Treat each citation as an independent reference and resolve PDFs for *all* of them.
    - Read the package `README.md`. Look for a `## References` heading, citations like `[N]`, RFC numbers, eprint links, or DOI/conference references. Build a list `papers = [(short-name, role, citation)]` where `role` describes which part of the implementation the paper covers (e.g. "main protocol", "derandomisation", "notation only", "background"). The README's prose usually makes the role explicit ("we follow X for the OT extension; Y for the derandomisation"); if it doesn't, mark the role as `unknown` and ask the user.
    - For each paper in the list, look for its PDF in a GitHub markdown comment in the README of the form `<!-- paper: <short-name> <path-or-url> <optional-relevant-section> -->`, `<!-- pdf[<short-name>]: <path> [<optional-relevant-section>]-->`, or any unambiguous `<!-- … -->` pointer. Multiple comments → one per paper. The path is typically relative to the package or repo root and are often from the repo-wide `docs/papers/` directory. Note that filenames there generally encode the citation key (`KOS15.pdf`, `Maurer09.pdf`, `rfc9180.pdf`).
    - Match PDFs to citations by short-name / filename / first-page title. Don't assume a 1:1 mapping — sometimes one PDF covers multiple cited works (a journal version subsuming a conference one), and sometimes a citation has no PDF because the README only uses it for context.
    - **If any citation that the code actually relies on is missing a PDF:** list every missing one with its expected drop location (`<pkg>/.docs/<short-name>.pdf` or `docs/papers/<short-name>.pdf`). Do not guess at the contents from a citation alone. If only a *background* citation is missing (paper is named in the README but no protocol step depends on it), note it but continue; mark the affected sections as best-effort.
    - **For each PDF you find:** read it (`Read` tool on the `.pdf`). Internalise the system model, adversary model, assumptions, the protocol description (figures/algorithms), and the security theorems' preconditions. You are looking for invariants the implementation must preserve, not a literature summary. Keep notes per paper — findings will need to attribute back.
    - When papers overlap on the same protocol step (e.g. KOS15 and SoftSpokenOT both describe a consistency check), record which one the code claims to follow at that point. The README typically pins this ("Figure 10 of KOS15"); if it doesn't, that's itself a question for the user.
    - If the README itself notes deviations or design decisions ("we replace coin-tossing with Fiat-Shamir", "we use notation from Figure 10 of …"), record those as known-and-acknowledged drift, scoped to the paper they apply to; don't double-flag them later.

3. **Spec discovery.**
    - A "spec" here means a normative description of the protocol that lives in the repo, separate from the paper. It can take several forms:
        - **Pseudocode in the README** (algorithm box, numbered steps, protocol description in math/LaTeX).
        - **Figure/algorithm citations in code comments** (e.g. `// Step 3 of Figure 10 of KOS15`, `// implements Fig. 4`).
        - **An RFC** (e.g. RFC 9180 for `pkg/encryption/hpke`). Treat the RFC as the spec; the README is a usage guide.
        - **A standalone in-repo design doc** (e.g. `SPEC.md`, `docs/spec.pdf`).
    - If you find a spec, list every concrete claim it makes (round structure, message contents, validation rules, ranges, hash inputs, transcript labels, error conditions). When the spec stitches together multiple papers, annotate each claim with which paper it traces to (per the README's role assignment from step 2).
    - **If paper(s) and spec exist:** cross-check them first. Run the consistency check pairwise: spec ↔ each cited paper that the spec quotes from. Paraphrase drift is OK; semantic drift (different message contents, different range, missing check, swapped verifier/prover roles) is a finding before you even look at the code.
    - **If multiple papers exist without an in-repo spec:** the cross-check is between papers, but only where they overlap. Identical sub-protocols described in two papers should produce the same wire format; if the code mixes step 3 from paper A with step 4 from paper B, ensure the seam is well-defined and not a silent mash-up.
    - If only one reference exists, that one is your spec. If no PDF and no spec exist but the README claims to implement a paper, the README's prose is the spec — note that the spec is informal.

4. **Compliance walk.** Walk the package code with the paper(s)/spec open. When more than one paper is in play, keep track of which one each code region is supposed to follow (use the `role` mapping from step 2 plus any in-code citations like `// Fig. 4 of KOS15`). Findings must attribute the discrepancy to a specific paper — `[deviation vs. KOS15 §4.2]` is more useful than `[deviation vs. paper]`. For each public-facing protocol step, check:
    - **System model & setup**: group, curve, modulus size, security parameter, statistical parameter — does the code's choice match the paper's? Are the constants in `params.go` / constructors defensible against the paper's claims?
    - **Adversary model**: malicious vs. semi-honest, static vs. adaptive, threshold structure. The package's doc comment / `doc.go` should state this; if it doesn't match the paper, flag it.
    - **Round / message structure**: number of rounds, who sends what, in what order. Cross-reference `messages.go` / `rounds.go` against the paper's protocol figure.
    - **Algebraic / cryptographic steps**: every commitment, challenge, response, hash input, transcript label. A different transcript label or hash domain separator is a wire-format vulnerability, not a nit.
    - **Range / membership checks**: every "where $x \in […]$" or "$g \in G$" in the paper must show up as a check in the constructor or unmarshaller. Missing range checks frequently anchor a security reduction — flag them as deviations even if the paper buries them in a footnote.
    - **Random sampling**: distributions match (uniform on $\mathbb{Z}_q$, geometric, discrete Gaussian, …). Wrong distribution = broken reduction.
    - **Soundness / ZK / extraction**: if the paper specifies a soundness error of $2^{-\lambda}$, find the parameter that produces it. If extraction requires two distinct challenges, ensure the challenge space supports it.
    - **Fiat-Shamir / non-interactive transforms**: hash inputs must include everything the paper says (statement, all prior messages, public parameters). Missing inputs → real attacks.
    - **Honest / adversarial path parity**: the simulator/extractor in the paper produces values from the same distribution as the honest prover. In code, the equivocation paths and the honest paths should agree on ranges, encodings, and validations. Mismatches are silent breaks of ZK or soundness.
    - **Identifiable abort**: if the paper specifies that misbehaviour is identifiable (and to whom), the code's abort errors must use `base.IdentifiableAbortPartyIDTag` or `pkg/base/errors.go:ErrAbort` accordingly. A non-identifiable abort where the paper requires identifiability is a deviation.

5. **Categorise findings.** For each item, decide:
    - **Deviation**: the code does the wrong thing relative to the paper/spec. Could break security; pin to the paper section.
    - **Missing**: a step / check / input the paper requires that the code omits.
    - **Addition**: a step / check the code performs that the paper doesn't mention. Often benign (defensive validation), occasionally harmful (extra branch leaks information, extra check changes the distribution). Decide and label.
    - **Acknowledged drift**: a deviation the README explicitly calls out. Restate it once for the user's awareness, not as a finding.

6. **Output as GitHub-flavoured markdown.** Use headers, **bold** severity tags, and `code` spans for paths so the terminal renders cleanly. Don't wrap the whole report in a fenced code block. Template:

    ```
    ## Spec compliance — `<pkg>`

    **References:**
    - `<short-name-A>` — <role: main protocol / sub-protocol / notation / background>. PDF: `<path>` _or_ `<missing — user must drop PDF at …>`
    - `<short-name-B>` — <role>. PDF: `<path>` _or_ `<missing>`
    - …

    **In-repo spec:** <README §, RFC number, `SPEC.md`, or "none">
    **Acknowledged drift (from README):** <one-liner each, scoped to the paper it applies to, or "none">

    ### Spec ↔ Paper consistency

    - `<short-name-A>` ↔ spec: <"consistent" or specific drift>
    - `<short-name-B>` ↔ spec: <…>
    - `<short-name-A>` ↔ `<short-name-B>` (where they overlap): <…>

    _(Drop bullets that don't apply. If only one paper and no separate spec, write "single reference; no cross-check needed".)_

    ### Findings

    - **[deviation vs. KOS15 §3.2]** `file.go:42` — code does X; paper Fig. 4 says Y
      - _Impact:_ <one sentence on what breaks (soundness / ZK / correctness / interop)>
    - **[missing vs. SoftSpokenOT §4]** `file.go:99` — paper requires range check `0 ≤ r < q`; constructor accepts any `*big.Int`
      - _Impact:_ …
    - **[addition vs. all references]** `file.go:120` — code performs extra check `X`; not in any cited paper
      - _Impact:_ benign / changes distribution / leaks bit
    - **[question vs. MR19]** `file.go:150` — paper is ambiguous about Z; current code does W. Confirm with author / paper appendix.

    _(If none: "No findings.")_

    ### Summary

    **Counts:** N deviation, N missing, N addition, N question.
    **Per-paper coverage:** `KOS15`: N findings; `SoftSpokenOT`: N; `MR19`: N.
    **Highest-risk:** `path:line` (vs. `<short-name>` §X) — <reduction or property at stake>.
    ```

    Severity tags must be one of `[deviation vs. <ref>]`, `[missing vs. <ref>]`, `[addition vs. <ref|all references>]`, `[question vs. <ref>]` and always bolded. The `<ref>` is the paper short-name (or `spec` for the in-repo spec, or `all references` when the addition contradicts every cited source). Order findings as: deviations first, then missing, then additions, then questions; within each bucket order by paper short-name (alphabetical), then file path, then line.

## Don'ts

- Don't audit error wrapping, doc-comment style, or other purely stylistic concerns — that's the `audit` skill's job. Stay on spec semantics.
- Don't recite the paper. The user has it. Cite section/figure/equation numbers.
- Don't claim "matches the paper" without naming the section you compared against.
- Don't infer the paper's content from the README's prose summary. If the PDF is missing, say so and stop — a paraphrase of a citation is not a spec.
- Don't edit code.
- Don't flag "the code uses notation X but the paper uses Y" if the README documents the renaming. That's acknowledged drift.
- Don't conflate "the code differs from the paper" with "the code is wrong" without naming the security property at risk. A deviation that doesn't change soundness/ZK/correctness/interop is a question, not a deviation.

## Caveats

- Papers and specs often disagree with each other (especially eprint v1 vs. v3 vs. proceedings version). If the README pins a specific version, use that one. If not, note which version you read and which sections you couldn't reconcile — let the user pick.
- Some packages cite a paper for *intuition* but actually implement a folklore variant or a different paper's protocol. If the code clearly tracks a different reference than the cited paper, flag it under `[deviation vs. <ref>]` and ask the user which is canonical.
- When a package cites multiple papers and the code switches references mid-protocol (e.g. notation from KOS15 §2 but verification from SoftSpokenOT §4), the seam is the highest-risk region. Read both papers' versions of the boundary step and confirm the code's hybrid is well-defined and not silently combining incompatible assumptions.
- RFCs: treat MUST / SHALL as deviations when violated, SHOULD as questions, MAY as informational. Don't downgrade a violated MUST to a nit.
- For interactive protocols, also sanity-check the messages on the wire (CBOR encoding, transcript inclusion). A protocol that's correct in pseudocode but encodes ambiguously over the wire is still broken — that's `messages.go` / domain-separator territory.
