EXTRA_DIST = ca-key.pem ca.pem common.sh server-cert.pem server-key.pem test1.config \
	test1.passwd test-user-cert.config user-cert.pem user-key.pem test3.config test-iroute.config \
	user-config/test user-config-opt/test test-pass-script.config test-multi-cookie.config test-pam.config \
	test-stress.config user-cert-wrong.pem connect-script test-group.passwd \
	test-group-pass.config user-group-cert.pem user-group-key.pem test-user-group-cert.config \
	test-user-group-cert-no-pass.config docker-common.sh

SUBDIRS = docker-ocserv

dist_check_SCRIPTS = test-pass test-pass-cert test-cert test-iroute test-pass-script \
	test-multi-cookie test-pam test-stress full-test test-group-pass test-pass-group-cert \
	ocpasswd-test test-pass-group-cert-no-pass unix-test test-pass-opt-cert

TESTS = test-pass test-pass-cert test-cert test-iroute test-pass-script \
	test-multi-cookie full-test test-group-pass test-pass-group-cert \
	ocpasswd-test test-pass-group-cert-no-pass unix-test test-pass-opt-cert

TESTS_ENVIRONMENT = srcdir="$(srcdir)" \
	top_builddir="$(top_builddir)"
