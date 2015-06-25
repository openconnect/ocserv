EXTRA_DIST = ca-key.pem ca.pem common.sh server-cert.pem server-key.pem test1.config \
	test1.passwd test-user-cert.config user-cert.pem user-key.pem test3.config test-iroute.config \
	user-config/test user-config-opt/test test-pass-script.config test-multi-cookie.config \
	test-stress.config user-cert-wrong.pem connect-script test-group.passwd \
	test-group-pass.config user-group-cert.pem user-group-key.pem test-user-group-cert.config \
	test-user-group-cert-no-pass.config docker-common.sh test-cookie-timeout.config \
	test-cookie-timeout-2.config user-config-explicit/test test-explicit-ip.config \
	test-explicit-ip user-config-explicit/test2 user-config-explicit/test3 \
	user-config-explicit/test4 test-pass-opt-cert.config test-gssapi.config \
	test-ban.config test-sighup.config test-gssapi-local-map.config \
	test-cookie-invalidation.config test-enc-key2.config test-enc-key.config \
	server-key-ossl.pem server-key-p8.pem

SUBDIRS = docker-ocserv docker-kerberos

dist_check_SCRIPTS = test-pass test-pass-cert test-cert test-iroute test-pass-script \
	test-multi-cookie test-stress full-test test-group-pass test-pass-group-cert \
	ocpasswd-test test-pass-group-cert-no-pass unix-test test-pass-opt-cert \
	test-cookie-timeout test-cookie-timeout-2 radius-test test-explicit-ip \
	radius-test test-gssapi kerberos-test pam-test test-ban test-sighup \
	test-cookie-invalidation radius-test-config test-enc-key


AM_CPPFLAGS = \
	-I$(top_srcdir)/src/ \
	-I$(top_builddir)/src/ \
	-I$(top_srcdir)/gl/ \
	-I$(top_builddir)/gl/ \
	-I$(top_srcdir)/ \
	-I$(top_builddir)/
kkdcp_parsing_SOURCES = ../src/config-kkdcp.c kkdcp-parsing.c
kkdcp_parsing_LDADD = ../gl/libgnu.a $(LIBTALLOC_LIBS)

json_escape_SOURCES = ../src/common-json.c json-escape.c
json_escape_LDADD = ../gl/libgnu.a $(LIBTALLOC_LIBS)

ipv4_prefix_SOURCES = ../src/common.c ../src/common.h ipv4-prefix.c
ipv4_prefix_LDADD = ../gl/libgnu.a $(LIBTALLOC_LIBS)

ipv6_prefix_SOURCES = ../src/common.c ../src/common.h ipv6-prefix.c
ipv6_prefix_LDADD = ../gl/libgnu.a $(LIBTALLOC_LIBS)

check_PROGRAMS = ipv4-prefix ipv6-prefix kkdcp-parsing json-escape

TESTS = test-pass test-pass-cert test-cert test-iroute test-pass-script \
	test-multi-cookie full-test test-group-pass test-pass-group-cert \
	ocpasswd-test test-pass-group-cert-no-pass unix-test test-pass-opt-cert \
	test-cookie-timeout test-cookie-timeout-2 test-explicit-ip radius-test \
	test-gssapi kerberos-test pam-test test-ban test-sighup ipv4-prefix \
	radius-test-config kkdcp-parsing json-escape test-enc-key

TESTS_ENVIRONMENT = srcdir="$(srcdir)" \
	top_builddir="$(top_builddir)"
