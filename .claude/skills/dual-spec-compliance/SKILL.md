---
name: dual-spec-compliance
description: Run spec-compliance twice in parallel — once in this Claude session, once via OpenAI's Codex CLI — then merge the findings into unique-to-each / agreed-by-both buckets followed by both raw reports. Use when the user says "dual-spec-compliance <target>" or wants a second-opinion check of paper/spec/reference-implementation alignment for a package.
effort: max
---

You are running the `spec-compliance` skill twice — locally as Claude, and remotely via the `codex` CLI — and merging the results. Be terse. The user wants the union of findings, not two separate reports.

ARGUMENTS: `<target>` — a package directory under `pkg/` (e.g. `pkg/proofs/internal/meta/maurer09`, `pkg/base/base58`). Pass it through verbatim; don't second-guess the form.

## Steps

1. **Preflight.** Run `command -v codex` via Bash. If it errors, stop and tell the user to install the OpenAI Codex CLI (`npm i -g @openai/codex` or equivalent) and authenticate.

2. **Capture the target.** Treat the user's argument as an opaque string `<T>`. Derive a filesystem-safe slug `<S>` (replace `/`, `:`, `..`, `#`, spaces with `_`) for use in tmp filenames.

3. **Build the Codex prompt.** Read `.claude/skills/spec-compliance/SKILL.md` and append a final line `ARGUMENTS: <T>`. Write the combined text to `/tmp/dual-spec-compliance-prompt-<S>.md`.

4. **Launch Codex in the background.** Use Bash with `run_in_background: true`. Pipe the prompt via stdin — the spec-compliance skill starts with `---` (YAML frontmatter), which codex's arg parser treats as a flag separator and rejects with exit 2 if passed positionally:
   ```
   cat /tmp/dual-spec-compliance-prompt-<S>.md | \
     codex exec --skip-git-repo-check --sandbox read-only --full-auto - \
     > /tmp/dual-spec-compliance-codex-<S>.md 2>&1
   ```
   `--full-auto` is required for non-interactive background use (otherwise codex blocks on approval prompts). `--sandbox read-only` keeps codex from touching the working tree. You'll be notified when it finishes. Do not poll.

5. **In parallel, run spec-compliance yourself** by following `.claude/skills/spec-compliance/SKILL.md` for target `<T>`. Resolve every `<!-- pdf|paper|spec|code[…]: … -->` directive, fetch URLs via `WebFetch`, read PDFs via `Read`, and produce the full report (template and all). Hold it in memory; do **not** print it yet.

6. **When the background task completes, read** `/tmp/dual-spec-compliance-codex-<S>.md`. If it's empty or errored, skip to step 8 and note the dual leg failed — don't suppress your own findings to fit the template.

7. **Merge.** Walk both reports finding-by-finding. Two findings match if they cite the same `file.go:line` (±a few lines) **and** target the same reference anchor (same paper §/figure, same spec MUST clause, same upstream function), or describe the same root cause attributed to the same reference in different words. A finding cited against `KOS15 §3.2` and one cited against `RFC9180 §4.1` are *not* matches even if they touch the same line — they're describing different obligations. Preserve each finding's original severity tag (`[deviation vs. <ref>]`, `[missing vs. <ref>]`, `[addition vs. <ref|all references>]`, `[question vs. <ref>]`) and original wording — do not paraphrase. For agreed-by-both findings:
    - Prefer the more specific reference anchor if the two diverge in precision (`KOS15 §3.2 Thm 3 cond. (1)` over `KOS15 §3`).
    - If the kinds disagree (e.g. one says `[deviation]`, the other says `[question]`), cite both: `[deviation vs. KOS15 §3.2 — Claude] / [question vs. KOS15 §3.2 — Codex]`.
    - Keep the `_Impact:_` sub-bullet from whichever side has the more concrete property-at-stake (soundness / ZK / interop / round-trip). If both have one, keep both, attributed.

8. **Print the merged report** in this exact order:

   ```
   ## Dual spec-compliance — `<T>`

   **References (union):**
   - `<short-name-A>` (paper) — <role>. Locator: `<status>` (Claude) / `<status>` (Codex)
   - `<short-name-B>` (spec) — <role>. Locator: `<status>` (Claude) / `<status>` (Codex)
   - `<short-name-C>` (code) — <role>. Locator: `<status>` (Claude) / `<status>` (Codex)

   _(If the two agents disagree on which references exist, list the union and note the disagreement on the affected rows.)_

   **In-repo spec:** <synthesised; note disagreement if any>
   **Acknowledged drift (from README):** <one-liner each, or "none">

   ### Reference ↔ Reference consistency

   - `<short-name-A>` ↔ in-repo spec: <verdict — note disagreement between Claude and Codex if any>
   - `<short-name-B>` ↔ `<short-name-C>` (where they overlap): <…>

   ### Findings unique to Claude
   - **[deviation vs. KOS15 §3.2]** `file.go:42` — …
     - _Impact:_ …

   ### Findings unique to Codex
   - **[missing vs. RFC9180 §4.1 (MUST)]** `file.go:99` — …
     - _Impact:_ …

   ### Findings agreed by both
   - **[deviation vs. bitcoin/base58.cpp:DecodeBase58]** `base58.go:88` — …
     - _Impact (Claude):_ …
     - _Impact (Codex):_ …

   ### Summary

   **Counts (union):** N deviation, N missing, N addition, N question.
   **Per-reference coverage:** `<short-name-A>` (paper): N findings; `<short-name-B>` (spec): N; `<short-name-C>` (code): N.
   **Highest-risk:** `path:line` (vs. `<short-name>` §X) — <property at stake>.

   ---

   ### Raw — Claude

   <verbatim Claude spec-compliance output>

   ### Raw — Codex

   <verbatim Codex spec-compliance output>
   ```

   If a bucket is empty, write `_None._` rather than omitting the header — the user wants to see at a glance whether each agent found something the other missed. Order findings within each bucket as spec-compliance prescribes: deviations first, then missing, then additions, then questions; within each kind, order by reference short-name (alphabetical), then file path, then line.

## Don'ts

- Don't drop a finding because the other side missed it. Bucketing exists precisely to surface those.
- Don't paraphrase severity tags or finding text in the buckets — copy them verbatim. Only the trailing `Summary` is synthesised.
- Don't merge findings that cite different references even if they're on the same line. A `[deviation vs. KOS15]` and a `[deviation vs. RFC9180]` on `file.go:42` are two findings, not one — they're claiming the line violates two different obligations.
- Don't post the report anywhere; just print. No PR comments, no commits.
- Don't strip the raw reports — they're the audit trail for the merge.
- Don't run `codex exec` in the foreground; it blocks long enough that running spec-compliance yourself in parallel is the whole point.
- Don't edit code (the inner spec-compliance skill forbids it; the dual wrapper inherits that).
- Don't fetch references twice — the inner skill is responsible for resolving directives. If Claude resolved a PDF and Codex didn't (e.g. because the PDF is in a developer-local `.docs/`), surface the asymmetry rather than re-fetching for Codex's benefit.

## Caveats

- Codex inherits cwd and shell env, so `git` auth and repo state carry over. PDFs in `.docs/` (gitignored) and `docs/papers/` are visible to both as long as the working tree has them. URLs resolved via `WebFetch` are Claude-only — Codex's URL fetch may be blocked by its sandbox, so expect occasional asymmetry on `<!-- spec[…]: <url> -->` and `<!-- code[…]: <url> -->` directives. Surface these as "Locator: resolved (Claude) / unresolved (Codex)" rather than discarding Codex's findings on the affected reference.
- Codex output is whatever its model decides to produce; it may not follow the spec-compliance template exactly (severity tags, reference-↔-reference section, per-reference coverage). Bucket what's there; don't try to rewrite it. If Codex omits the consistency cross-check or per-reference counts, fall back to your own.
- If the two reports disagree on a fact (e.g. one claims `Anchor.PreImage` is verified at `Extract`, the other claims it isn't), put it in `unique to <agent>` rather than `agreed-by-both`. Don't arbitrate — that's the user's job.
- Reference attribution is the highest-signal part of the merge: a finding the user can trace back to "paper §3.2 condition (1)" or "RFC 9180 §4.1 MUST" is far more actionable than a generic "deviation". Preserve those anchors verbatim from each side; don't normalise them across agents.
- If only one side resolved a reference (e.g. Claude `WebFetch`ed the wiki, Codex didn't), the agent that didn't resolve will inevitably under-report findings against that reference. Note this in the per-reference coverage line so the user knows the asymmetry is structural, not a real disagreement.
- Reductions / paper-alignment findings are easy to miss for whichever agent didn't resolve the underlying PDF/URL. If only one side cites a particular reference, treat that as a real finding under `unique to <agent>`, not noise.
