noinst_SCRIPTS = runtest.sh

TESTS = runalltests.sh

EXTRA_DIST = $(TESTS) runtest.sh.in test_inetdomain.py test_zone.py test_matcher.py test_dispatch.py test_nat.py test_log.py test_session.py test_keybridge.py

.PHONY: mkzorp
mkzorp:
	make -C ../../zorp

runtest.sh: mkzorp
