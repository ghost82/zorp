#!/bin/bash

ERROR=0

for test in $srcdir/test_*.py
do
    python $test 2> /tmp/test_result;
    if [ $? -ne 0 ]
        then
            echo "FAILED test: $test"
            cat /tmp/test_result;
            ERROR=1
    fi
    rm /tmp/test_result
done

exit $ERROR
