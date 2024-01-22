#!/usr/bin/env sh

packageName=$1
if [[ -z $packageName ]]; then
    echo "Usage: ./run_benchmark.sh <packageName>"
    exit 1
fi

files=$(find . -type f -print | grep '_test.go' | xargs grep -l 'func Benchmark')
COUNTER=0

for file in ${files}
do
    funcs=$(grep -oE 'func (Benchmark\w*)' $file)
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
        go test $parentDir -test.bench $func
        set +x
    done
done

if [[ $COUNTER -eq 0 ]]; then
    echo "********WARNING: No benchmarks found in $packageName********"
fi
