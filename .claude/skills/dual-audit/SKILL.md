---
name: dual-audit
description: Run audit twice in parallel — once in this Claude session, once via OpenAI's Codex CLI — then merge the findings into unique-to-each / agreed-by-both buckets followed by both raw reports. Use when the user says "dual-audit <target>" or wants a second-opinion audit of a file, package, or diff.
effort: max
---

You are running the `audit` skill twice — locally as Claude, and remotely via the `codex` CLI — and merging the results. Be terse. The user wants the union of findings, not two separate reports.

ARGUMENTS: `<target>` — a file path, package path, or diff reference (e.g. `pkg/foo/bar.go`, `pkg/mpc/signatures/...`, `origin/master..HEAD`, `#<PR>`). Pass it through verbatim; don't second-guess the form.

## Steps

1. **Preflight.** Run `command -v codex` via Bash. If it errors, stop and tell the user to install the OpenAI Codex CLI (`npm i -g @openai/codex` or equivalent) and authenticate.

2. **Capture the target.** Treat the user's argument as an opaque string `<T>`. Derive a filesystem-safe slug `<S>` (replace `/`, `:`, `..`, `#`, spaces with `_`) for use in tmp filenames.

3. **Build the Codex prompt.** Read `.claude/skills/audit/SKILL.md` and append a final line `ARGUMENTS: <T>`. Write the combined text to `/tmp/dual-audit-prompt-<S>.md`.

4. **Launch Codex in the background.** Use Bash with `run_in_background: true`. Pipe the prompt via stdin — the audit skill starts with `---` (YAML frontmatter), which codex's arg parser treats as a flag separator and rejects with exit 2 if passed positionally:
   ```
   cat /tmp/dual-audit-prompt-<S>.md | \
     codex exec --skip-git-repo-check --sandbox read-only --full-auto - \
     > /tmp/dual-audit-codex-<S>.md 2>&1
   ```
   `--full-auto` is required for non-interactive background use (otherwise codex blocks on approval prompts). `--sandbox read-only` keeps codex from touching the working tree. You'll be notified when it finishes. Do not poll.

5. **In parallel, run audit yourself** by following `.claude/skills/audit/SKILL.md` for target `<T>`. Produce the full report (template and all). Hold it in memory; do **not** print it yet.

6. **When the background task completes, read** `/tmp/dual-audit-codex-<S>.md`. If it's empty or errored, skip to step 8 and note the dual leg failed — don't suppress your own findings to fit the template.

7. **Merge.** Walk both reports finding-by-finding. Two findings match if they cite the same `file.go:line` (±a few lines) or describe the same root cause in different words. Preserve each finding's original severity tag (`[critical]`/`[major]`/`[minor]`/`[info]`) and original wording — do not paraphrase. For agreed-by-both findings, prefer the more specific phrasing of the two and cite both severities if they disagree (e.g. `[critical — Claude] / [minor — Codex]`). Keep the `_Fix:_` sub-bullet from whichever side has the more actionable suggestion; if both have one, keep both, attributed.

8. **Print the merged report** in this exact order:

   ```
   ## Dual audit — <T>

   **Scope:** <in-scope / experimental — take the stricter of the two if they disagree, and note the disagreement>

   ### Findings unique to Claude
   - **[critical]** `file.go:42` — …
     - _Fix:_ …

   ### Findings unique to Codex
   - **[critical]** `file.go:99` — …
     - _Fix:_ …

   ### Findings agreed by both
   - **[critical]** `file.go:123` — …
     - _Fix (Claude):_ …
     - _Fix (Codex):_ …

   ### Summary

   **Counts (union):** N critical, N major, N minor, N info.
   **Highest-risk:** `path:line` — finding.

   ---

   ### Raw — Claude

   <verbatim Claude audit output>

   ### Raw — Codex

   <verbatim Codex audit output>
   ```

   If a bucket is empty, write `_None._` rather than omitting the header — the user wants to see at a glance whether each agent found something the other missed. Order findings within each bucket by severity (critical first), then by file path, matching audit's own ordering rule.

## Don'ts

- Don't drop a finding because the other side missed it. Bucketing exists precisely to surface those.
- Don't paraphrase severity tags or finding text in the buckets — copy them verbatim. Only the trailing `Summary` is synthesized.
- Don't post the audit anywhere; just print. No PR comments, no commits.
- Don't strip the raw reports — they're the audit trail for the merge.
- Don't run `codex exec` in the foreground; it blocks long enough that running audit yourself in parallel is the whole point.
- Don't edit code (the inner audit skill forbids it; the dual wrapper inherits that).

## Caveats

- Codex inherits cwd and shell env, so `git` auth and repo state carry over. If the target is a PR/diff, ensure `gh` auth works locally first.
- Codex output is whatever its model decides to produce; it may not follow the audit template exactly (severity tags, scope line, etc.). Bucket what's there; don't try to rewrite it. If Codex omits scope, fall back to your own scope determination.
- If the two reports disagree on a fact (e.g. one claims a missing range check, the other claims it's enforced upstream), put it in `unique to <agent>` rather than `agreed-by-both`. Don't arbitrate — that's the user's job.
- Reductions / paper-alignment findings are easy to miss for whichever agent didn't read the `.docs/` PDF. If only one side cites the paper, treat that as a real finding, not noise.
