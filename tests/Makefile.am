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
	server-key-ossl.pem server-key-p8.pem proxyproto-unix-test user-cn.pem \
	user-cert-testuser.pem test-stress test-user-config.config user-config/testuser \
	test-sighup-key-change.config test-sighup-key-change.config user-config/testipnet \
	user-cert-testipnet.pem

SUBDIRS = docker-ocserv docker-kerberos

dist_check_SCRIPTS = test-iroute test-pass-script \
	test-multi-cookie full-test ocpasswd-test unix-test test-pass-opt-cert \
	test-cookie-timeout test-cookie-timeout-2 radius-test test-explicit-ip \
	radius-test test-gssapi kerberos-test pam-test test-ban \
	test-cookie-invalidation radius-test-config proxyproto-test \
	proxyproto-unix-test pam-noauth-test otp-test test-user-config \
	firewall-test test-append-routes reload-info-test \
	firewall-neg-test

if HAVE_CWRAP
dist_check_SCRIPTS += test-pass test-pass-cert test-cert test-group-pass \
	test-pass-group-cert test-pass-group-cert-no-pass test-sighup \
	test-enc-key test-sighup-key-change
endif

AM_CPPFLAGS = \
	$(LIBOPTS_CFLAGS) \
	$(LIBTALLOC_CFLAGS) \
	-I$(top_srcdir)/src/ \
	-I$(top_builddir)/src/ \
	-I$(top_srcdir)/src/common/ \
	-I$(top_builddir)/src/common/ \
	-I$(top_srcdir)/gl/ \
	-I$(top_builddir)/gl/ \
	-I$(top_srcdir)/ \
	-I$(top_builddir)/

if LOCAL_TALLOC
AM_CPPFLAGS += -I$(srcdir)/../src/ccan/talloc
endif

if LOCAL_HTTP_PARSER
AM_CPPFLAGS += -I$(srcdir)/../src/http-parser/
endif

if LOCAL_PROTOBUF_C
AM_CPPFLAGS += -I$(srcdir)/../src/protobuf/
endif

kkdcp_parsing_SOURCES = kkdcp-parsing.c
kkdcp_parsing_LDADD = ../gl/libgnu.a $(LIBTALLOC_LIBS) ../src/ccan/libccan.a

json_escape_SOURCES = json-escape.c
json_escape_LDADD = ../gl/libgnu.a $(LIBTALLOC_LIBS) ../src/ccan/libccan.a

ipv4_prefix_SOURCES = ipv4-prefix.c
ipv4_prefix_LDADD = ../gl/libgnu.a $(LIBTALLOC_LIBS) ../src/ccan/libccan.a

ban_ips_CPPFLAGS = $(AM_CPPFLAGS) -DDISABLE_LOGS
ban_ips_SOURCES = ban-ips.c
ban_ips_LDADD = ../gl/libgnu.a $(LIBTALLOC_LIBS) ../src/ccan/libccan.a

str_test_SOURCES = str-test.c
str_test_LDADD = ../gl/libgnu.a $(LIBTALLOC_LIBS) ../src/ccan/libccan.a

ipv6_prefix_SOURCES = ipv6-prefix.c
ipv6_prefix_LDADD = ../gl/libgnu.a $(LIBTALLOC_LIBS) ../src/ccan/libccan.a

human_addr_CPPFLAGS = $(AM_CPPFLAGS) 
human_addr_SOURCES = human_addr.c
human_addr_LDADD = ../gl/libgnu.a $(LIBTALLOC_LIBS) ../src/ccan/libccan.a

port_parsing_LDADD = ../gl/libgnu.a $(LIBTALLOC_LIBS) ../src/ccan/libccan.a

check_PROGRAMS = str-test ipv4-prefix ipv6-prefix kkdcp-parsing json-escape ban-ips \
	port-parsing human_addr

TESTS = $(dist_check_SCRIPTS) $(check_PROGRAMS)

TESTS_ENVIRONMENT = srcdir="$(srcdir)" \
	top_builddir="$(top_builddir)"
