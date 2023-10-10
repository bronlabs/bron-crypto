#!/bin/bash

set -x

packageName=$1
if [[ -z $packageName ]]; then
    echo "Usage: ./run_fuzz.sh <packageName>"
    exit 1
fi

files=$(grep -r --include='**_test.go' --files-with-matches 'func Fuzz' .)
COUNTER=0

for file in ${files}
do
    funcs=$(grep -oE 'func (Fuzz\w*)' $file)
    for func in ${funcs}
    do
        if [[ $func == "func" ]]; then
            continue
        fi
        if [[ $file != *$packageName* ]]; then
            continue
        fi
        parentDir=$(dirname $file)
        let COUNTER++
        go test $parentDir -fuzz="^$func\$" -parallel=10 -fuzztime=120s
    done
done

if [[ $COUNTER -eq 0 ]]; then
    echo "********WARNING: No fuzz tests found in $packageName********"
fi

