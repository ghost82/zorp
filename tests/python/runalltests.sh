#!/bin/bash

pwd
ok=0
fail=0
for test in $srcdir/test_*.py
do
	sh ./runtest.sh $test;
	rc=$?
	case "$rc" in
		0) 
			echo -e "##########################\n#### OK: $test ####\n##########################"
			ok=$[ $ok + 1 ]
	      		;;
	      	*)
			echo -e "##########################\n#### FAIL: $test ####\n##########################"
	      		fail=$[ $fail + 1 ]
	      		;;
	esac
done

echo "ok: $ok"
echo "fail: $fail"

exit $fail
