include ../src/common.mk

EXTRA_DIST = certs/ca-key.pem certs/ca.pem common.sh certs/server-cert.pem \
	certs/server-key.pem data/test1.config data/pam/nss-group.in data/pam/nss-passwd.in \
	data/pam/users.oath.templ data/test-pam-noauth.config data/test-pam.passwd \
	data/test1.passwd data/test-user-cert.config certs/user-cert.pem certs/user-key.pem \
	data/test3.config data/test-iroute.config data/test-pam.config \
	user-config/test user-config-opt/test data/test-pass-script.config data/test-multi-cookie.config \
	data/test-stress.config certs/user-cert-wrong.pem connect-script data/test-group.passwd \
	data/test-group-pass.config certs/user-group-cert.pem certs/user-group-key.pem \
	data/test-user-group-cert.config data/pam/ocserv.in data/pam/passdb.templ data/pam-single/passdb.templ \
	data/test-user-group-cert-no-pass.config docker-common.sh data/test-cookie-timeout.config \
	data/test-cookie-timeout-2.config user-config-explicit/test data/test-explicit-ip.config \
	test-explicit-ip user-config-explicit/test2 user-config-explicit/test3 \
	user-config-explicit/test4 data/test-pass-opt-cert.config data/test-gssapi.config \
	data/test-ban.config data/test-sighup.config data/test-gssapi-local-map.config \
	data/test-cookie-invalidation.config data/test-enc-key2.config data/test-enc-key.config \
	certs/server-key-ossl.pem certs/server-key-p8.pem proxyproto-unix-test certs/user-cn.pem \
	certs/user-cert-testuser.pem test-stress data/test-user-config.config user-config/testuser \
	data/test-sighup-key-change.config data/test-sighup-key-change.config user-config/testipnet \
	certs/user-cert-testipnet.pem certs/user-cert-invalid.pem certs/server-cert-ca.pem

SUBDIRS = docker-ocserv docker-kerberos

dist_check_SCRIPTS =  ocpasswd-test

if ENABLE_ROOT_TESTS
#docker tests
dist_check_SCRIPTS += radius-test full-test unix-test kerberos-test radius-test-config \
	proxyproto-test proxyproto-unix-test otp-test firewall-test firewall-neg-test \
	reload-info-test radius-group-test

#other root requiring tests
dist_check_SCRIPTS += test-iroute test-multi-cookie test-pass-script test-pass-opt-cert \
	test-cookie-timeout test-cookie-timeout-2 test-explicit-ip test-gssapi \
	test-cookie-invalidation test-user-config test-append-routes test-ban
endif

if HAVE_CWRAP
dist_check_SCRIPTS += test-pass test-pass-cert test-cert test-group-pass \
	test-pass-group-cert test-pass-group-cert-no-pass test-sighup \
	test-enc-key test-sighup-key-change test-get-cert

if HAVE_CWRAP_PAM
dist_check_SCRIPTS += test-pam test-pam-noauth
endif

endif


AM_CPPFLAGS += \
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

kkdcp_parsing_SOURCES = kkdcp-parsing.c
kkdcp_parsing_LDADD = ../gl/libgnu.a $(LIBTALLOC_LIBS) ../src/ccan/libccan.a

json_escape_SOURCES = json-escape.c
json_escape_LDADD = ../gl/libgnu.a $(LIBTALLOC_LIBS) ../src/ccan/libccan.a

url_escape_SOURCES = url-escape.c
url_escape_LDADD = ../gl/libgnu.a $(LIBTALLOC_LIBS) ../src/ccan/libccan.a

html_escape_SOURCES = html-escape.c
html_escape_LDADD = ../gl/libgnu.a $(LIBTALLOC_LIBS) ../src/ccan/libccan.a

ipv4_prefix_SOURCES = ipv4-prefix.c
ipv4_prefix_LDADD = ../gl/libgnu.a $(LIBTALLOC_LIBS) ../src/ccan/libccan.a

ban_ips_CPPFLAGS = $(AM_CPPFLAGS) -DDISABLE_LOGS
ban_ips_SOURCES = ban-ips.c
ban_ips_LDADD = ../gl/libgnu.a $(LIBTALLOC_LIBS) ../src/ccan/libccan.a

str_test_SOURCES = str-test.c
str_test_LDADD = ../gl/libgnu.a $(LIBTALLOC_LIBS) ../src/ccan/libccan.a

str_test2_SOURCES = str-test2.c
str_test2_LDADD = ../gl/libgnu.a $(LIBTALLOC_LIBS) ../src/ccan/libccan.a

ipv6_prefix_SOURCES = ipv6-prefix.c
ipv6_prefix_LDADD = ../gl/libgnu.a $(LIBTALLOC_LIBS) ../src/ccan/libccan.a

human_addr_CPPFLAGS = $(AM_CPPFLAGS) 
human_addr_SOURCES = human_addr.c
human_addr_LDADD = ../gl/libgnu.a $(LIBTALLOC_LIBS) ../src/ccan/libccan.a

valid_hostname_LDADD = ../gl/libgnu.a

port_parsing_LDADD = ../gl/libgnu.a $(LIBTALLOC_LIBS) ../src/ccan/libccan.a

check_PROGRAMS = str-test str-test2 ipv4-prefix ipv6-prefix kkdcp-parsing json-escape ban-ips \
	port-parsing human_addr valid-hostname url-escape html-escape


TESTS = $(dist_check_SCRIPTS) $(check_PROGRAMS)

TESTS_ENVIRONMENT = srcdir="$(srcdir)" \
	top_builddir="$(top_builddir)"
