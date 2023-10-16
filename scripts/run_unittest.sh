#!/bin/sh -x

packageName=$1
flag=$2
if [[ -z $packageName ]]; then
    echo "Usage: ./run_unittest.sh <packageName>"
    exit 1
fi

files=$(find . -name "$packageName")

for file in ${files}
do
    if [[ $file != *$packageName* ]]; then
        continue
    fi
    parentDir=$(dirname $file)
    go test $flag -timeout 0s "$parentDir/$packageName/..."
done
