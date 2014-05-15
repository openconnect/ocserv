EXTRA_DIST = ca-key.pem ca.pem common.sh server-cert.pem server-key.pem test1.config \
	test1.passwd test-user-cert.config user-cert.pem user-key.pem test3.config test-iroute.config \
	user-config/test test-pass-script.config test-multi-cookie.config test-pam.config \
	test-stress.config user-cert-wrong.pem connect-script kill-parent.sh

dist_check_SCRIPTS = test-pass test-pass-cert test-cert test-iroute test-pass-script \
	test-multi-cookie test-pam test-stress full-test

TESTS = test-pass test-pass-cert test-cert test-iroute test-pass-script \
	test-multi-cookie full-test

TESTS_ENVIRONMENT = srcdir="$(srcdir)" \
	top_builddir="$(top_builddir)"
