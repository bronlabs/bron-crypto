---
name: dual-review
description: Run pr-review twice in parallel — once in this Claude session, once via OpenAI's Codex CLI — then merge the findings into unique-to-each / agreed-by-both buckets followed by both raw reports. Use when the user says "dual-review PR #N" or wants a second-opinion review.
effort: max
---

You are running the `pr-review` skill twice — locally as Claude, and remotely via the `codex` CLI — and merging the results. Be terse. The user wants the union of findings, not two separate reports.

ARGUMENTS: `<PR number>` (with or without leading `#`).

## Steps

1. **Preflight.** Run `command -v codex` via Bash. If it errors, stop and tell the user to install the OpenAI Codex CLI (`npm i -g @openai/codex` or equivalent) and authenticate.

2. **Resolve PR number.** Strip a leading `#` if present. Call it `<N>`.

3. **Build the Codex prompt.** Read `.claude/skills/pr-review/SKILL.md` and append a final line `ARGUMENTS: #<N>`. Write the combined text to `/tmp/dual-review-prompt-<N>.md`.

4. **Launch Codex in the background.** Use Bash with `run_in_background: true`. Pipe the prompt via stdin — the pr-review skill starts with `---` (YAML frontmatter), which codex's arg parser treats as a flag separator and rejects with exit 2 if passed positionally:
   ```
   cat /tmp/dual-review-prompt-<N>.md | \
     codex exec --skip-git-repo-check --sandbox read-only --full-auto - \
     > /tmp/dual-review-codex-<N>.md 2>&1
   ```
   `--full-auto` is required for non-interactive background use (otherwise codex blocks on approval prompts). `--sandbox read-only` keeps codex from touching the working tree. You'll be notified when it finishes. Do not poll.

5. **In parallel, run pr-review yourself** by following `.claude/skills/pr-review/SKILL.md` for PR `<N>`. Produce the full report (template and all). Hold it in memory; do **not** print it yet.

6. **When the background task completes, read** `/tmp/dual-review-codex-<N>.md`. If it's empty or errored, skip to step 8 and note the dual leg failed — don't suppress your own findings to fit the template.

7. **Merge.** Walk both reports finding-by-finding. Two findings match if they cite the same `file.go:line` (±a few lines) or describe the same root cause in different words. Preserve each finding's original severity tag (`[blocker]`/`[nit]`/`[question]`) and original wording — do not paraphrase. For agreed-by-both findings, prefer the more specific phrasing of the two and cite both severities if they disagree (e.g. `[blocker — Claude] / [nit — Codex]`).

8. **Print the merged report** in this exact order:

   ```
   ## PR #<N> — Dual review

   ### Findings unique to Claude
   - **[blocker]** `file.go:42` — …

   ### Findings unique to Codex
   - **[blocker]** `file.go:99` — …

   ### Findings agreed by both
   - **[blocker]** `file.go:123` — …

   ### Description vs. diff
   <one line: union of both reports' findings>

   ### Recommendation
   <one short paragraph merging both recommendations>

   ---

   ### Raw — Claude

   <verbatim Claude pr-review output>

   ### Raw — Codex

   <verbatim Codex pr-review output>
   ```

   If a bucket is empty, write `_None._` rather than omitting the header — the user wants to see at a glance whether each agent found something the other missed.

## Don'ts

- Don't drop a finding because the other side missed it. Bucketing exists precisely to surface those.
- Don't paraphrase severity tags or finding text in the buckets — copy them verbatim. Only the trailing `Description vs. diff` and `Recommendation` are synthesized.
- Don't post the review (no `gh pr review`, no comments). Just print.
- Don't strip the raw reports — they're the audit trail for the merge.
- Don't run `codex exec` in the foreground; it blocks long enough that running pr-review yourself in parallel is the whole point.

## Caveats

- Codex inherits cwd and shell env, so `gh` and `git` auth carry over. If `gh auth status` fails for Claude, it'll fail for Codex too.
- Codex output is whatever its model decides to produce; it may not follow the pr-review template exactly. Bucket what's there; don't try to rewrite it.
- If the two reports disagree on a fact (e.g. one claims a line panics, the other claims it's safe), put it in `unique to <agent>` rather than `agreed-by-both`. Don't arbitrate — that's the user's job.
