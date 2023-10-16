#!/bin/sh -x

packageName=$1
if [[ -z $packageName ]]; then
    echo "Usage: ./run_benchmark.sh <packageName>"
    exit 1
fi

files=$(grep -r --include='**_test.go' --files-with-matches 'func Benchmark' .)
COUNTER=0

for file in ${files}
do
    funcs=$(grep -oE 'func (Benchmark\w*)' $file)
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
        go test $parentDir -test.bench $func
    done
done

if [[ $COUNTER -eq 0 ]]; then
    echo "********WARNING: No benchmarks found in $packageName********"
fi
