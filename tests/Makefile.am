EXTRA_DIST = ca-key.pem ca.pem common.sh server-cert.pem server-key.pem test1.config \
	test1.passwd test-user-cert.config user-cert.pem user-key.pem test3.config test-iroute.config \
	user-config/test user-config-opt/test test-pass-script.config test-multi-cookie.config \
	test-stress.config user-cert-wrong.pem connect-script test-group.passwd \
	test-group-pass.config user-group-cert.pem user-group-key.pem test-user-group-cert.config \
	test-user-group-cert-no-pass.config docker-common.sh test-cookie-timeout.config \
	test-cookie-timeout-2.config user-config-explicit/test test-explicit-ip.config \
	test-explicit-ip user-config-explicit/test2 user-config-explicit/test3 \
	user-config-explicit/test4 test-pass-opt-cert.config test-gssapi.config \
	test-ban.config test-sighup.config test-gssapi-local-map.config

SUBDIRS = docker-ocserv docker-kerberos

dist_check_SCRIPTS = test-pass test-pass-cert test-cert test-iroute test-pass-script \
	test-multi-cookie test-stress full-test test-group-pass test-pass-group-cert \
	ocpasswd-test test-pass-group-cert-no-pass unix-test test-pass-opt-cert \
	test-cookie-timeout test-cookie-timeout-2 radius-test test-explicit-ip \
	radius-test test-gssapi kerberos-test pam-test test-ban test-sighup

TESTS = test-pass test-pass-cert test-cert test-iroute test-pass-script \
	test-multi-cookie full-test test-group-pass test-pass-group-cert \
	ocpasswd-test test-pass-group-cert-no-pass unix-test test-pass-opt-cert \
	test-cookie-timeout test-cookie-timeout-2 test-explicit-ip radius-test \
	test-gssapi kerberos-test pam-test test-ban test-sighup

TESTS_ENVIRONMENT = srcdir="$(srcdir)" \
	top_builddir="$(top_builddir)"
