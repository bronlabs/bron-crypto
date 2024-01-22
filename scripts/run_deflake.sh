#!/usr/bin/env sh

packageName=$1
flag=$2
if [[ -z $packageName ]]; then
    echo "Usage: ./run_unittest.sh <packageName>"
    exit 1
fi

files=$(find . -name "$packageName")

for file in ${files}
do
        case "$file" in
          *"$packageName"*)
            ;; # Do nothing if $file is a substring of $packageName
          *)
            continue
            ;;
        esac
    parentDir=$(dirname $file)
    set -x
    go test -count=1000 $flag -timeout 0s "$parentDir/$packageName/..."
    set +x
done
