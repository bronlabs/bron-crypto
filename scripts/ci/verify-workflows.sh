#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
workflow_dir="$root/.github/workflows"

if rg -n 'runs-on:\s*self-hosted' "$workflow_dir"; then
	echo "workflows must not run untrusted code on self-hosted runners" >&2
	exit 1
fi

missing_permissions=0
for workflow in "$workflow_dir"/*.yml "$workflow_dir"/*.yaml; do
	[[ -e "$workflow" ]] || continue
	if ! rg -q '^permissions:' "$workflow"; then
		echo "$workflow is missing explicit permissions" >&2
		missing_permissions=1
	fi
done
if [[ "$missing_permissions" -ne 0 ]]; then
	exit 1
fi

missing_timeout=0
for workflow in "$workflow_dir"/*.yml "$workflow_dir"/*.yaml; do
	[[ -e "$workflow" ]] || continue
	if ! rg -q '^\s+timeout-minutes:' "$workflow"; then
		echo "$workflow is missing job timeout-minutes" >&2
		missing_timeout=1
	fi
done
if [[ "$missing_timeout" -ne 0 ]]; then
	exit 1
fi

uses_status=0
while IFS=: read -r file line text; do
	ref="${text##*@}"
	ref="${ref%% *}"
	ref="${ref%%#*}"
	if [[ ! "$ref" =~ ^[0-9a-f]{40}$ ]]; then
		echo "$file:$line uses an action that is not pinned to a full SHA: $text" >&2
		uses_status=1
	fi
done < <(rg -n 'uses:\s*[^[:space:]]+@' "$workflow_dir")

exit "$uses_status"
