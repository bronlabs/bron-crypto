#!/usr/bin/env sh

packageName=$1
flag=$2
if [[ -z $packageName ]]; then
    echo "Usage: ./scripts/run_fuzz.sh <packageName>"
    exit 1
fi

files=$(find . -type f -print | grep '_test.go' | xargs grep -l 'func Fuzz')
COUNTER=0

for file in ${files}
do
    funcs=$(grep -oE 'func (Fuzz\w*)' $file)
    for func in ${funcs}
    do
        if [[ $func == "func" ]]; then
            continue
        fi
        case "$file" in
          *"$packageName"*)
            ;; # Do nothing if $file is a substring of $packageName
          *)
            continue
            ;;
        esac
        parentDir=$(dirname $file)
        let COUNTER++
        set -x
        go test $parentDir -fuzz="^$func\$" $flag
        set +x
    done
done

if [[ $COUNTER -eq 0 ]]; then
    echo "********WARNING: No fuzz tests found in $packageName********"
fi

