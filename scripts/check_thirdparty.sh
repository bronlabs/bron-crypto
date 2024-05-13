#!/usr/bin/env bash
set -e

function check() {
  local manifest_file=$1
  local third_party_home
  local remote_manifest_file
  local local_manifest_file

  third_party_home=$(dirname "${manifest_file}")
  remote_manifest_file=$(mktemp)
  local_manifest_file=$(mktemp)

  while read -r line; do
    local remote_repo
    local local_path
    local commit_hash
    local remote_repo_dir

    remote_repo=$(echo "${line}" | cut -d' ' -f1)
    local_path=$(echo "${line}" | cut -d' ' -f2)
    commit_hash=$(echo "${line}" | cut -d' ' -f3)
    remote_repo_dir=$(mktemp -d)

    local local_repo_dir="${third_party_home}/${local_path}"

    # The idea here is simple.
    # We take a list of the files from upstream repo that were changed since the last commit we sync from...
    git clone -q --branch master --single-branch --depth 1 "${remote_repo}" "${remote_repo_dir}"
    pushd "${remote_repo_dir}" >/dev/null
    git fetch -q --depth 1 origin "${commit_hash}"
    git diff --name-only "${commit_hash}..master" | sort > "${remote_manifest_file}"
    popd >/dev/null

    # ...then we take a list of the files we keep in our repo...
    pushd "${local_repo_dir}" >/dev/null
    # shellcheck disable=SC2035
    find * -type f -print | sort > "${local_manifest_file}"
    popd >/dev/null

    # ...and we print these that appear in both sets.
    comm -12 "${remote_manifest_file}" "${local_manifest_file}" | sed -e "s|^|${local_path}/|"
  done < "${manifest_file}"
}


check "$1"
