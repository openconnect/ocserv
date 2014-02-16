EXTRA_DIST = ca-key.pem ca.pem common.sh server-cert.pem server-key.pem test1.config \
	test1.passwd test2.config user-cert.pem user-key.pem test3.config test-iroute.config \
	user-config/test test-pass-script.config test-multi-cookie.config test-pam.config \
	test-stress.config

dist_check_SCRIPTS = test-pass test-pass-cert test-cert test-iroute test-pass-script \
	test-multi-cookie test-pam test-stress

TESTS = test-pass test-pass-cert test-cert test-iroute test-pass-script \
	test-multi-cookie

TESTS_ENVIRONMENT = srcdir="$(srcdir)" \
	top_builddir="$(top_builddir)"
