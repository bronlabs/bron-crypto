#!/bin/sh

# Variables
repo_url="https://github.com/golang/go.git"
local_folder_path="pkg/hashing/tmmohash/keyedblock"
remote_folder_path="temp_repo/src/crypto/aes"

# Clone the repository and navigate to it
git clone --depth 1 "$repo_url" temp_repo

# Check if the specific files have any updates
if diff -q "$local_folder_path/asm_amd64.s" "$remote_folder_path/asm_amd64.s" >/dev/null; then
     echo "asm_amd64.s are identical"
else
     echo "asm_amd64.s are not identical"
     exit 1
fi
if diff -q "$local_folder_path/asm_arm64.s" "$remote_folder_path/asm_arm64.s" >/dev/null; then
     echo "asm_arm64.s are identical"
else
     echo "asm_arm64.s are not identical"
     exit 1
fi
if diff -q "$local_folder_path/asm_ppc64x.s" "$remote_folder_path/asm_ppc64x.s" >/dev/null; then
     echo "asm_ppc64x.s are identical"
else
     echo "asm_ppc64x.s are not identical"
     exit 1
fi

# Clean up
rm -rf temp_repo