---
name: spec-compliance
description: Determine whether a package faithfully implements its cited reference — academic paper, normative spec (RFC / wiki / design doc), or upstream reference implementation code. Use when the user asks to check paper/spec/reference-implementation compliance, reduction alignment, byte-exact parity with an upstream, or whether the code matches the protocol description in a README, paper, RFC, or `code` directive.
effort: max
---

You are checking whether a package implements its cited reference(s) correctly. References can be academic papers, normative specs (RFC / wiki / design doc), or upstream reference implementations. Be skeptical, cite `file:line` plus the right anchor in each reference (paper §/figure for papers, MUST/SHALL clauses for specs, file/function for code), and don't fix — report. The point is alignment with the cited description, not stylistic review.

## Steps

1. **Identify the target.** A package directory under `pkg/`. Ask if unclear. If the user names a file, treat the file's package as the target.

2. **Reference discovery.** Packages often cite **more than one** reference — e.g. one paper for the main protocol, one for a sub-protocol, one for the notation, one for a transformation (Fiat–Shamir, derandomisation), or a non-academic spec / reference implementation for an encoding or wire format. Treat each citation as an independent reference and resolve *all* of them.
    - Read the package `README.md`. Look for a `## References` heading, citations like `[N]`, RFC numbers, eprint links, DOI/conference references, wiki links, or pointers to upstream source code. Build a list `refs = [(short-name, kind, role, citation, locator)]` where:
        - `kind ∈ {paper, spec, code}`. `paper` means an academic publication (read as a PDF). `spec` means a normative non-academic description — RFC HTML, wiki page, design doc, BIP/SLIP. `code` means a reference implementation — a source file, a Git repo, a directory of code. Pick `paper` even when the README also links to a wiki page if the *primary* reference is the academic paper; pick `spec` when no paper exists but a wiki/RFC does; pick `code` when the package is implementing-by-reference an existing implementation (e.g. a Bitcoin re-implementation tracking `bitcoin/src/base58.cpp`).
        - `role` describes which part of the implementation this reference covers ("main protocol", "derandomisation", "notation only", "background", "wire format", "reference implementation", …). If the README doesn't make the role explicit, mark `unknown` and ask.
        - `locator` is the directive pointer (resolved below). May be `None` if no directive is present.
    - For each reference, look for its locator in a GitHub markdown comment in the README. Recognised directive forms:
        - `<!-- paper[<short-name>]: <path-or-url> [<section>] -->` or `<!-- pdf[<short-name>]: <path> [<section>] -->` — academic paper as PDF (preferred form for `kind=paper`).
        - `<!-- spec[<short-name>]: <path-or-url> [<section>] -->` — non-academic normative reference. The path-or-url can be a URL (RFC, wiki, BIP) or a local file (`docs/specs/foo.md`, an in-repo `SPEC.md`). The optional `<section>` narrows attention.
        - `<!-- code[<short-name>]: <path-or-url> [<section>] -->` — reference implementation. The path-or-url can be a URL to a source file (e.g. `https://github.com/bitcoin/bitcoin/blob/master/src/base58.cpp`), a path to a clone in `thirdparty/`, or an in-repo file. The optional `<section>` may name a function/region.
        - The bracketed `<short-name>` may be omitted if the README cites only one reference (so `<!-- spec: <url> -->` is also accepted; treat the package name as the implicit short-name).
        - Multiple comments → one per reference.
    - **Resolve each locator** according to its kind:
        - `paper`/`pdf`: use `Read` on the PDF. Filenames in `<pkg>/.docs/` or `docs/papers/` typically encode the short-name (`KOS15.pdf`, `Maurer09.pdf`, `rfc9180.pdf`). PDF locations are gitignored per `.gitignore:63` for `.docs/`, populated locally; `docs/papers/` is repo-wide.
        - `spec`: use `WebFetch` if it's a URL, `Read` if it's a local path. Treat MUST/SHALL as load-bearing; record every algorithm box and every prose constraint that pins behaviour.
        - `code`: prefer `Read` if a local copy exists (clone, vendored copy, in-repo path). Otherwise use `WebFetch` on the source URL. Read the *whole* function or region the README points to, not just the name. For a multi-file reference implementation, ask the user which file(s) you should treat as canonical before fetching everything blindly.
    - **If a reference the code actually relies on cannot be resolved:** list it with the expected drop location or a re-fetch instruction (`<pkg>/.docs/<short>.pdf`, `docs/papers/<short>.pdf`, `<url>`, or "add `<!-- code[<short>]: <url> -->` to README"). Do not guess from a citation alone. *Background* citations (named in the README but no protocol step depends on them) can be noted-and-skipped; mark affected sections best-effort.
    - **For each reference you resolve:** internalise it. For papers: system model, adversary model, assumptions, protocol description (figures/algorithms), security theorems' preconditions. For specs: every normative claim (MUST/SHALL/SHOULD), every algorithm, every wire constant. For reference code: every observable behaviour the package is meant to match — input validation, error semantics, byte-exact output, edge cases (empty input, leading zeros, max length). Keep notes *per reference* — findings will need to attribute back.
    - When references overlap on the same step (e.g. KOS15 and SoftSpokenOT both describe a consistency check; an RFC and a reference implementation both describe a wire format), record which one the code claims to follow at that point. The README typically pins this ("Figure 10 of KOS15"; "matching `base58.cpp:DecodeBase58`"); if it doesn't, that's itself a question for the user.
    - If the README notes deviations or design decisions ("we replace coin-tossing with Fiat-Shamir", "we use notation from Figure 10 of …", "we omit the legacy character `0` even though some `code` references accept it"), record those as known-and-acknowledged drift, scoped to the reference they apply to; don't double-flag them later.

3. **In-repo spec discovery.** This is *additional* to the directive-pointed references collected in step 2 — it captures normative content that lives inside the repo without a `<!-- ... -->` pointer.
    - In-repo specs include:
        - **Pseudocode in the README** (algorithm box, numbered steps, protocol description in math/LaTeX).
        - **Figure/algorithm citations in code comments** (e.g. `// Step 3 of Figure 10 of KOS15`, `// implements Fig. 4`, `// matches DecodeBase58 in bitcoin/src/base58.cpp`).
        - **An RFC** (e.g. RFC 9180 for `pkg/encryption/hpke`). If the RFC is reachable via `<!-- spec[...]: <rfc-url> -->` it's already in step 2; if it's only named in prose, capture it here as informal.
        - **A standalone in-repo design doc** (e.g. `SPEC.md`, `docs/spec.pdf`).
    - If you find an in-repo spec, list every concrete claim it makes (round structure, message contents, validation rules, ranges, hash inputs, transcript labels, error conditions). When the spec stitches together multiple references, annotate each claim with which reference it traces to (per the `role` mapping from step 2).
    - **If both step-2 references and an in-repo spec exist:** cross-check them first. Run the consistency check pairwise: in-repo spec ↔ each step-2 reference the spec quotes from. Paraphrase drift is OK; semantic drift (different message contents, different range, missing check, swapped verifier/prover roles, byte-exact mismatch with reference code) is a finding before you even look at the package's code.
    - **If multiple step-2 references exist without an in-repo spec:** the cross-check is between references, but only where they overlap. Identical sub-protocols described in two papers should produce the same wire format. A wiki spec and a reference implementation should agree byte-for-byte; if they don't, prefer the reference code's behaviour and treat the spec as documentation of intent (or vice versa, depending on which one upstream consumers actually depend on). If the code mixes step 3 from reference A with step 4 from reference B, ensure the seam is well-defined and not a silent mash-up.
    - If only one reference exists, that one is your spec. If no resolved reference and no in-repo spec exist but the README claims to implement something, the README's prose is the spec — note that the spec is informal.

4. **Compliance walk.** Walk the package code with the resolved reference(s) open. When more than one reference is in play, keep track of which one each code region is supposed to follow (use the `role` mapping from step 2 plus any in-code citations like `// Fig. 4 of KOS15` or `// matches DecodeBase58`). Findings must attribute the discrepancy to a specific reference — `[deviation vs. KOS15 §4.2]` or `[deviation vs. bitcoin/base58.cpp:DecodeBase58]` is more useful than `[deviation vs. paper]`.

    The checklist below is reference-kind-aware. Apply each row only when the corresponding reference kind is in scope; skip rows that don't apply to the package under review.

    For `paper` references — focus on the formal model:
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

    For `spec` references — focus on normative wire / behavioural claims:
    - **Wire format / encoding**: every byte the spec pins down (lengths, magic constants, alphabets, domain-separator strings, padding, endianness). Off-by-one or wrong-endian are interop deviations.
    - **Algorithm steps**: pseudocode in the spec maps to a specific function in the code. Each numbered step should have a corresponding code line; missing or reordered steps are findings.
    - **Normative keywords**: MUST / SHALL violations are deviations; SHOULD violations are questions; MAY differences are informational. Don't downgrade a violated MUST to a nit.
    - **Test vectors**: if the spec ships test vectors, run them through the code mentally (or, if practical, via the existing test suite) — a vector that doesn't round-trip is a deviation, not a nit.
    - **Error semantics**: many specs pin the *kind* of failure (e.g. "MUST reject", "MUST return InvalidLength"). The code's error variants should match the spec's failure taxonomy.

    For `code` references — focus on byte-exact behaviour parity:
    - **Public function correspondence**: map each public function in the package to the matching function in the reference implementation. A function with no counterpart is either an addition (flag and reason about safety) or a missed feature (flag).
    - **Input validation**: every check the reference performs (length bounds, alphabet, leading-zero handling, sign bits, …) should appear in the package, in the same place (constructor / unmarshaller / decoder). Missing checks are deviations.
    - **Edge cases**: empty input, single-byte input, max-length input, all-zero input, leading/trailing zeros, leading sign characters. Reference-implementation behaviour on these is often the de-facto spec; mismatches break round-trip with anyone using the upstream.
    - **Error paths**: when the reference returns an error, the package should too — and ideally the *kind* of error should be preserved (an upstream "invalid character" should not become a generic "decode failed"). Going further than the reference (rejecting input the reference accepts) is an addition; going less far is a deviation.
    - **Byte-exact output**: for encoders, identical input → identical output bytes/string. For decoders, the inverse round-trip must reproduce the original bytes (with leading-zero rules etc.). If the reference's tests are reachable, treat passing all of them as the bar.
    - **Side-effects / non-determinism**: the reference may rely on locale, RNG, or environmental state. Note these as porting questions if the package mirrors the reference too literally.

5. **Categorise findings.** For each item, decide:
    - **Deviation**: the code does the wrong thing relative to the paper/spec. Could break security; pin to the paper section.
    - **Missing**: a step / check / input the paper requires that the code omits.
    - **Addition**: a step / check the code performs that the paper doesn't mention. Often benign (defensive validation), occasionally harmful (extra branch leaks information, extra check changes the distribution). Decide and label.
    - **Acknowledged drift**: a deviation the README explicitly calls out. Restate it once for the user's awareness, not as a finding.

6. **Output as GitHub-flavoured markdown.** Use headers, **bold** severity tags, and `code` spans for paths so the terminal renders cleanly. Don't wrap the whole report in a fenced code block. Template:

    ```
    ## Spec compliance — `<pkg>`

    **References:**
    - `<short-name-A>` (paper) — <role>. Locator: `<path>` _or_ `<missing — user must drop PDF at …>`
    - `<short-name-B>` (spec) — <role>. Locator: `<url-or-path>` _or_ `<unresolved>`
    - `<short-name-C>` (code) — <role>. Locator: `<url-or-path>` _or_ `<unresolved>`
    - …

    **In-repo spec:** <README §, RFC number, `SPEC.md`, or "none">
    **Acknowledged drift (from README):** <one-liner each, scoped to the reference it applies to, or "none">

    ### Reference ↔ Reference consistency

    - `<short-name-A>` ↔ in-repo spec: <"consistent" or specific drift>
    - `<short-name-B>` ↔ `<short-name-C>` (where they overlap): <…>
    - …

    _(Drop bullets that don't apply. If only one reference and no separate in-repo spec, write "single reference; no cross-check needed".)_

    ### Findings

    - **[deviation vs. KOS15 §3.2]** `file.go:42` — code does X; paper Fig. 4 says Y
      - _Impact:_ <one sentence on what breaks (soundness / ZK / correctness / interop)>
    - **[missing vs. RFC9180 §4.1 (MUST)]** `file.go:99` — spec requires `info` length check; decoder accepts any length
      - _Impact:_ interop / spec violation
    - **[deviation vs. bitcoin/base58.cpp:DecodeBase58]** `base58.go:88` — reference treats whitespace as a hard reject; this decoder silently skips it
      - _Impact:_ interop — strings that round-trip in upstream don't here
    - **[addition vs. all references]** `file.go:120` — code performs extra check `X`; not in any cited reference
      - _Impact:_ benign / changes distribution / leaks bit
    - **[question vs. MR19]** `file.go:150` — paper is ambiguous about Z; current code does W. Confirm with author / paper appendix.

    _(If none: "No findings.")_

    ### Summary

    **Counts:** N deviation, N missing, N addition, N question.
    **Per-reference coverage:** `KOS15` (paper): N findings; `RFC9180` (spec): N; `bitcoin/base58.cpp` (code): N.
    **Highest-risk:** `path:line` (vs. `<short-name>` §X) — <property at stake: soundness / ZK / interop / round-trip>.
    ```

    Severity tags must be one of `[deviation vs. <ref>]`, `[missing vs. <ref>]`, `[addition vs. <ref|all references>]`, `[question vs. <ref>]` and always bolded. The `<ref>` is the reference short-name (optionally suffixed with a section / function / line — e.g. `KOS15 §4.2`, `RFC9180 §4.1 (MUST)`, `bitcoin/base58.cpp:DecodeBase58`), or `spec` for the in-repo spec, or `all references` when the addition contradicts every cited source. Order findings as: deviations first, then missing, then additions, then questions; within each bucket order by reference short-name (alphabetical), then file path, then line.

## Don'ts

- Don't audit error wrapping, doc-comment style, or other purely stylistic concerns — that's the `audit` skill's job. Stay on spec semantics.
- Don't recite the reference. The user has it. Cite section/figure/equation numbers for papers and specs; cite file/function/line for code references.
- Don't claim "matches the reference" without naming the section/function you compared against.
- Don't infer a reference's content from the README's prose summary. If the locator is unresolved (PDF missing, URL fetch failed, file not found), say so and stop — a paraphrase of a citation is not a spec, and a wiki page name is not a spec either.
- Don't edit code.
- Don't flag "the code uses notation X but the paper uses Y" if the README documents the renaming. That's acknowledged drift.
- Don't conflate "the code differs from the reference" with "the code is wrong" without naming the property at risk. A deviation that doesn't change soundness / ZK / correctness / interop / round-trip is a question, not a deviation.
- Don't `WebFetch` an unbounded reference (e.g. an entire upstream repo) without scoping. Pull the specific file or section the directive names, or ask the user to scope it.

## Caveats

- Papers and specs often disagree with each other (especially eprint v1 vs. v3 vs. proceedings version, or RFC errata vs. base RFC). If the README pins a specific version, use that one. If not, note which version you read and which sections you couldn't reconcile — let the user pick.
- Some packages cite a paper for *intuition* but actually implement a folklore variant or a different reference's protocol. If the code clearly tracks a different reference than the cited one, flag it under `[deviation vs. <ref>]` and ask the user which is canonical.
- When a package cites multiple references and the code switches references mid-protocol (e.g. notation from KOS15 §2 but verification from SoftSpokenOT §4; or wire format from RFC X but error semantics from reference code Y), the seam is the highest-risk region. Read both references' versions of the boundary step and confirm the code's hybrid is well-defined and not silently combining incompatible assumptions.
- RFCs / specs: treat MUST / SHALL as deviations when violated, SHOULD as questions, MAY as informational. Don't downgrade a violated MUST to a nit.
- Reference implementations are *de facto* specs for their ecosystem. If the package's claim is "implements the same X as Bitcoin Core", then byte-exact parity with `bitcoin/base58.cpp` matters more than any wiki page that paraphrases the algorithm. Defer to the code reference when the spec and code disagree, unless the package's README explicitly says otherwise.
- For interactive protocols, also sanity-check the messages on the wire (CBOR encoding, transcript inclusion). A protocol that's correct in pseudocode but encodes ambiguously over the wire is still broken — that's `messages.go` / domain-separator territory.
- `WebFetch` on a URL gives you a snapshot in time and may miss content behind JavaScript, auth, or rate limits. If the fetch returns less than you expected, say so in the report rather than silently working with a partial reference.
