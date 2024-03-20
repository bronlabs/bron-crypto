#!/usr/bin/env sh

threshold=$1

mv cover.out cover.out.tmp
cat cover.out.tmp | grep -v "testutils" > cover.out
rm cover.out.tmp

# Generate coverage report
coverage=$(go tool cover -func=cover.out | grep "total:" | awk '{ print $3 }' | sed 's/%//g')

# Check if coverage is below the threshold
coverage_test=$(echo "$coverage<$threshold" | bc)
if [ $coverage_test -eq 1 ]; then
    echo "Total coverage $coverage% is below the threshold of $threshold%"
    exit 1
else
    echo "Total coverage is $coverage% - OK!. Threshold is $threshold%"
fi