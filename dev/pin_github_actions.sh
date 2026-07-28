#!/usr/bin/env bash
# Pin GitHub Actions to reviewed commits and check that the pins do not drift.
#
# The scan covers every YAML file in the checkout. That includes workflows,
# composite action.yml/action.yaml files, and workflow templates outside
# .github/workflows/. Local actions (./...) are intentionally not external
# supply-chain references and are left alone.
#
# Pin format: owner/repository@<40-char-sha> # vX.Y.Z
# Requires: gh CLI authenticated when run without --check.

set -euo pipefail

SCRIPT_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
ROOT=${PIN_CHECK_ROOT:-$SCRIPT_ROOT}

usage() {
  echo "usage: bash dev/pin_github_actions.sh [--check]" >&2
}

mode=pin
if [[ ${1:-} == "--check" ]]; then
  mode=check
elif [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

# Enumerated from git's index rather than a filesystem walk with a denylist.
# A denylist only excludes the vendored directories someone remembered: the
# sibling repo roam-code hit exactly this, where a walk descended into a
# gitignored bench-repos/ tree of third-party checkouts and reported hundreds
# of deliberately-unpinned workflows that are not part of that repo's supply
# chain. Asking git inverts the default from "included unless listed" to
# "included only if tracked", which is also the correct scope on the merits:
# only what the repo ships can be pushed. Staged additions are still covered,
# since `git ls-files` reads the index.
mapfile -d '' files < <(
  if git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then
    git -C "$ROOT" ls-files -z -- '*.yml' '*.yaml' |
      while IFS= read -r -d '' rel; do printf '%s\0' "$ROOT/$rel"; done
  else
    find "$ROOT" -type f \( -name "*.yml" -o -name "*.yaml" \) \
      ! -path "$ROOT/.git/*" \
      ! -path "$ROOT/.venv/*" \
      ! -path "$ROOT/node_modules/*" \
      ! -path "$ROOT/dist/*" \
      ! -path "$ROOT/build/*" \
      -print0
  fi | sort -z
)

declare -a reference_files=()
declare -a reference_lines=()
declare -a reference_values=()
uses_pattern='^[[:space:]]*(-[[:space:]]*)?uses:[[:space:]]*([^[:space:]#]+)'

for file in "${files[@]}"; do
  relative=${file#"$ROOT"/}
  while IFS= read -r numbered_line || [[ -n $numbered_line ]]; do
    line_number=${numbered_line%%:*}
    content=${numbered_line#*:}
    if [[ $content =~ $uses_pattern ]]; then
      reference=${BASH_REMATCH[2]}
      [[ $reference == ./* ]] && continue
      reference_files+=("$relative")
      reference_lines+=("$line_number")
      reference_values+=("$reference")
    fi
  done < <(nl -ba -w1 -s: "$file")
done

is_sha_pin() {
  [[ $1 =~ ^[^@[:space:]]+@[0-9a-f]{40}$ ]]
}

has_version_comment() {
  local line=$1
  local reference=$2
  local suffix=${line#*"$reference"}
  [[ $suffix =~ ^[[:space:]]+#[[:space:]]*[^[:space:]] ]]
}

declare -a unpinned_files=()
declare -a unpinned_lines=()
declare -a unpinned_values=()
pinned_count=0

for index in "${!reference_values[@]}"; do
  file=${ROOT}/${reference_files[$index]}
  line=$(sed -n "${reference_lines[$index]}p" "$file")
  reference=${reference_values[$index]}
  if is_sha_pin "$reference" && has_version_comment "$line" "$reference"; then
    ((pinned_count += 1))
  else
    unpinned_files+=("${reference_files[$index]}")
    unpinned_lines+=("${reference_lines[$index]}")
    unpinned_values+=("$reference")
  fi
done

echo "[actions] found ${#reference_values[@]} uses references; $pinned_count already pinned."

if [[ $mode == check ]]; then
  for index in "${!unpinned_values[@]}"; do
    echo "${unpinned_files[$index]}:${unpinned_lines[$index]}: uses: ${unpinned_values[$index]}"
  done
  if [[ ${#unpinned_values[@]} -eq 0 ]]; then
    exit 0
  fi
  exit 1
fi

if [[ ${#unpinned_values[@]} -eq 0 ]]; then
  exit 0
fi

declare -A resolved=()
unresolved_count=0
for reference in "${unpinned_values[@]}"; do
  if is_sha_pin "$reference"; then
    echo "error: ${reference} is missing its trailing version comment; add it manually." >&2
    ((unresolved_count += 1))
    continue
  fi
  if [[ -z ${resolved[$reference]+x} ]]; then
    repository=${reference%@*}
    tag=${reference#*@}
    sha=$(gh api "repos/${repository}/commits/${tag}" --jq .sha)
    if ! [[ $sha =~ ^[0-9a-f]{40}$ ]]; then
      echo "error: gh returned an invalid commit SHA for ${reference}: ${sha}" >&2
      ((unresolved_count += 1))
      continue
    fi
    resolved[$reference]="${repository}@${sha}  # ${tag}"
    echo "pin: ${reference} -> ${resolved[$reference]}"
  fi
done

if (( unresolved_count != 0 )); then
  exit 1
fi

for index in "${!unpinned_values[@]}"; do
  reference=${unpinned_values[$index]}
  replacement=${resolved[$reference]-}
  [[ -n $replacement ]] || continue
  file=${ROOT}/${unpinned_files[$index]}
  escaped_reference=$(printf '%s\n' "$reference" | sed 's/[.[\*^$\\]/\\&/g')
  escaped_replacement=$(printf '%s\n' "$replacement" | sed 's/[&\\]/\\&/g')
  sed -i -E "s|${escaped_reference}([[:space:]]+#[^[:cntrl:]]*)?|${escaped_replacement}|g" "$file"
done

echo "Done. Re-run bash dev/pin_github_actions.sh --check before review."
