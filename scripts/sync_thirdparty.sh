#!/usr/bin/env sh

echo "Checking sync for thirdparty dependencies..."

# Create tmp folder and ensure it gets deleted
# shellcheck disable=SC2006
TMP_FOLDER=`mktemp -d`
if [ ! -e "$TMP_FOLDER" ]; then
    >&2 echo "Failed to create temp directory"
    exit 1
fi

trap "exit 1"                HUP INT PIPE QUIT TERM
trap 'rm -rf "$TMP_FOLDER"'  EXIT

# Check all the dependencies in `thirdparty`
ALL_SYNCED=true

# shellcheck disable=SC2002
cat thirdparty/manifest.txt | while read -r dependency; do
    echo " --> Syncing $dependency"
    dependency="thirdparty/${dependency}"
    cfg="${dependency}/.config"

    # read the config variables `dependencyRepository` & `dependencyCommit`
    if [ ! -e "$cfg" ]; then
        echo " ---> Dependency config file not found: $cfg"
        # shellcheck disable=SC2030
        ALL_SYNCED=false
    else 
        . "$cfg"
        echo " ---> Fetching repository $dependencyRepository, commit $dependencyCommit"

        # clone the dependency (most recent commit and dependencyCommit only)
        git clone -q --depth 1 "$dependencyRepository" "$TMP_FOLDER/$dependency"
        (cd "$TMP_FOLDER/$dependency" && git fetch -q --depth 1 origin "$dependencyCommit")

        # Find non-empty relative-path folders forked from the dependency, excluding the `.config` file
        (cd "$dependency"  && find . -type f ! -name .config | xargs dirname | sort -u) | while read -r dependencyFolder; do
            # Check for changes in each folder
            echo " ---> Checking $dependencyFolder"
            if [ ! -e "$TMP_FOLDER/$dependency/$dependencyFolder" ]; then
                echo " ---> Folder $dependencyFolder not found in $dependencyRepository"
                # shellcheck disable=SC2030
                ALL_SYNCED=false
                continue
            fi

            DEP_DIFF=$(cd "$TMP_FOLDER/$dependency" && git diff -z "${dependencyCommit}..master" "$dependencyFolder")
            # shellcheck disable=SC2039
            if [[ $DEP_DIFF ]]; then
                echo " ---> Found changes in $dependencyFolder (from $dependencyRepository)"
                echo "$DEP_DIFF"
                ALL_SYNCED=false
            fi
        done
    fi
done

# shellcheck disable=SC2031
if [ $ALL_SYNCED = false ]; then
    echo "...Finished. Some dependencies need syncing."
    exit 1
else
    echo "...Finished. All dependencies are up-to-date."
    exit 0
fi
