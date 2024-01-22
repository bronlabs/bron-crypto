#!/usr/bin/env sh

packageName=$1
if [[ -z $packageName ]]; then
    echo "Usage: ./run_cte.sh <packageName>"
    exit 1
fi

files=$(find . -type f -print | grep '_test.go' | xargs grep -l 'Test_MeasureConstantTime_')
COUNTER=0

for file in ${files}
do
    funcs=$(grep -oE 'func (Test_MeasureConstantTime_\w*)' $file)
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
        EXEC_TIME_TEST=1 go test -timeout 300s -run ^$func\$ $parentDir
        set +x
    done
done

if [[ $COUNTER -eq 0 ]]; then
    echo "********WARNING: No CTE tests found in $packageName********"
fi

