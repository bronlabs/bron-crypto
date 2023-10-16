#!/bin/sh -x

packageName=$1
if [[ -z $packageName ]]; then
    echo "Usage: ./run_cte.sh <packageName>"
    exit 1
fi

files=$(grep -r --include='**_test.go' --files-with-matches 'Test_MeasureConstantTime_' .)
COUNTER=0

for file in ${files}
do
    funcs=$(grep -oE 'func (Test_MeasureConstantTime_\w*)' $file)
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
        EXEC_TIME_TEST=1 go test -timeout 300s -run ^$func\$ $parentDir
    done
done

if [[ $COUNTER -eq 0 ]]; then
    echo "********WARNING: No CTE tests found in $packageName********"
fi

