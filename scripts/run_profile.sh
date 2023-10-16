#!/bin/sh -x

packageName=$1
if [[ -z $packageName ]]; then
    echo "Usage: ./run_profile.sh <packageName>"
    exit 1
fi

files=$(grep -r --include='**_test.go' --files-with-matches 'TestRunProfile' .)
COUNTER=0

for file in ${files}
do
    funcs=$(grep -oE 'func (TestRunProfile\w*)' $file)
    for func in ${funcs}
    do
        if [[ $func == "func" ]]; then
            continue
        fi
        if [[ $file != *$packageName* ]]; then
            continue
        fi
        parentDir=$(dirname $file)
        mkdir -p ${TMPDIR}${parentDir}
        let COUNTER++
        PROFILE_TEST=1 go test -timeout 300s -run ^$func\$ $parentDir -memprofile ${TMPDIR}${parentDir}/memprofile.out -cpuprofile ${TMPDIR}${parentDir}/cpuprofile.out
        go tool pprof -top ${TMPDIR}${parentDir}/memprofile.out | grep copperexchange
        go tool pprof -top ${TMPDIR}${parentDir}/cpuprofile.out | grep copperexchange
    done
done

if [[ $COUNTER -eq 0 ]]; then
    echo "********WARNING: No Profile tests found in $packageName********"
fi
