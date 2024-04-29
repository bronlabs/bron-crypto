#!/usr/bin/env sh

# shellcheck source-path=scripts/

echo "Checking sync for thirdparty dependencies..."

# Create tmp folder and ensure it gets deleted
TMP_FOLDER=$(mktemp -d)
if [ ! -e "$TMP_FOLDER" ]; then
    >&2 echo "Failed to create temp directory"
    exit 1
fi

# Avoiding the subshell problem by storing the ALL_SYNC flag in a file
SYNC_STATUS=$(mktemp)
if [ ! -e "$SYNC_STATUS" ]; then
    >&2 echo "Failed to create sync status temp file"
    exit 1
fi



# shellcheck disable=SC2317 # we trap this in an Exit.
cleanup() {
    echo "Cleaning up temporary files..."
    rm -rf "$TMP_FOLDER"
    rm -f "$SYNC_STATUS"

}

trap "exit 1"                HUP INT PIPE QUIT TERM
trap cleanup EXIT

# Check all the dependencies in `thirdparty`
echo "true" > "$SYNC_STATUS"

while read -r dependency; do
    echo " --> Syncing $dependency"
    dependency="thirdparty/${dependency}"
    cfg="${dependency}/.config"

    # read the config variables `dependencyRepository` & `dependencyCommit`
    if [ ! -e "$cfg" ]; then
        echo " ---> Dependency config file not found: $cfg"
        echo "false" > "$SYNC_STATUS"
    else
        # all configs look alike, so we specify one to help shellcheck parse things.
        # shellcheck source=../thirdparty/golang/crypto/.config
        . "${cfg}"
        echo " ---> Fetching repository $dependencyRepository, commit $dependencyCommit"

        # clone the dependency (most recent commit and dependencyCommit only)
        git clone -q --depth 1 "$dependencyRepository" "$TMP_FOLDER/$dependency"
        (cd "$TMP_FOLDER/$dependency" && git fetch -q --depth 1 origin "$dependencyCommit")

        # Find non-empty relative-path folders forked from the dependency, excluding the `.config` file
        (cd "$dependency"  && find . -type f ! -name .config -print0 | xargs -0 dirname | sort -u) | while read -r dependencyFolder; do
            # Check for changes in each folder
            echo " ---> Checking $dependencyFolder"
            if [ ! -e "$TMP_FOLDER/$dependency/$dependencyFolder" ]; then
                echo " ---> Folder $dependencyFolder not found in $dependencyRepository"
                echo "false" > "$SYNC_STATUS"
                continue
            fi

            DEP_DIFF=$(cd "$TMP_FOLDER/$dependency" && git ls-tree -r --name-only  git diff "${dependencyCommit}..master" "$dependencyFolder")
            if [ -n "$DEP_DIFF" ]; then
                echo " ---> Found changes in $dependencyFolder (from $dependencyRepository)"
                echo "$DEP_DIFF" | git apply --directory "$(pwd)/$dependency" -
                echo "false" > "$SYNC_STATUS"
            fi
        done
    fi
done < thirdparty/manifest.txt

ALL_SYNCED=$(cat "$SYNC_STATUS")

if [ "$ALL_SYNCED" = "false" ]; then
    echo "...Finished. Some dependencies need syncing."
    exit 1
else
    echo "...Finished. All dependencies are up-to-date."
    exit 0
fi
