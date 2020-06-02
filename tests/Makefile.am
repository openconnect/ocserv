include ../src/common.mk

EXTRA_DIST = certs/ca-key.pem certs/ca.pem ns.sh common.sh certs/server-cert.pem \
	certs/server-key.pem data/test1.config data/pam/nss-group.in data/pam/nss-passwd.in \
	data/pam/users.oath.templ data/test-pam-noauth.config data/test-pam.passwd \
	data/test1.passwd data/test-user-cert.config certs/user-cert.pem certs/user-key.pem \
	data/test3.config data/test-iroute.config data/test-pam.config data/test-vhost2.passwd \
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
	certs/user-cert-testipnet.pem certs/user-cert-invalid.pem certs/server-cert-ca.pem \
	data/test-san-cert.config certs/user-san-cert.pem data/test-vhost3.passwd \
	certs/server-cert-ed25519.pem certs/server-key-ed25519.pem data/test-ed25519.config \
	certs/server-cert-rsa-pss.pem certs/server-key-rsa-pss.pem data/test-rsa-pss.config \
	data/test-otp-cert.config data/test-otp.oath test-otp-cert data/test-otp.passwd \
	data/test-otp.config data/test-cert-opt-pass.config data/test-gssapi-opt-pass.config \
	certs/server-key-secp521r1.pem certs/server-cert-secp521r1.pem data/test-vhost-pass-cert.config \
	data/vhost.hosts data/multiple-routes.config data/haproxy-auth.cfg data/test-haproxy-auth.config \
	data/haproxy-connect.cfg data/test-haproxy-connect.config scripts/vpnc-script \
	data/test-traffic.config data/test-compression-lzs.config data/test-compression-lz4.config \
	certs/crl.pem server-cert-rsa-pss data/test-gssapi-opt-cert.config data/test-ciphers.config \
	cipher-common.sh data/config-per-group.config data/group-config/tost \
	data/raddb/access_reject data/raddb/accounting_response data/raddb/access_challenge data/raddb/acct_users \
	data/raddb/clients.conf data/raddb/radiusd.conf data/raddb/users \
	data/radiusclient/dictionary data/radiusclient/radiusclient.conf \
	data/radiusclient/servers data/radius.config data/radius-group.config data/radius-otp.config \
	data/test-udp-listen-host.config data/pam-kerberos/passdb.templ \
	data/test-max-same-1.config data/test-script-multi-user.config \
	sleep-connect-script data/test-psk-negotiate.config data/test-group-name.config \
	connect-ios-script data/apple-ios.config certs/kerberos-cert.pem \
	data/kdc.conf data/krb5.conf data/k5.KERBEROS.TEST data/kadm5.acl \
	data/ipv6-iface.config data/no-route-default.config data/no-route-group.config \
	data/group-config/group1

SUBDIRS = docker-ocserv

xfail_scripts =
dist_check_SCRIPTS =  ocpasswd-test

if GNUTLS_WITH_NEW_CERTS
dist_check_SCRIPTS += server-cert-ed25519 server-cert-rsa-pss
endif


if ENABLE_ROOT_TESTS
if ENABLE_DOCKER_TESTS
#docker tests
dist_check_SCRIPTS += unix-test \
	proxyproto-test proxyproto-v1-test proxyproto-unix-test \
	reload-info-test
endif

#other root requiring tests
dist_check_SCRIPTS += haproxy-connect test-iroute test-multi-cookie test-pass-script \
	test-cookie-timeout test-cookie-timeout-2 test-explicit-ip \
	test-cookie-invalidation test-user-config test-append-routes test-ban \
	multiple-routes json test-udp-listen-host test-max-same-1 test-script-multi-user \
	apple-ios ipv6-iface

if RADIUS_ENABLED
dist_check_SCRIPTS += radius-group radius-otp
endif

#other tests requiring nuttcp for traffic
if ENABLE_NUTTCP_TESTS
dist_check_SCRIPTS += traffic lz4-compression lzs-compression \
	aes256-cipher aes128-cipher oc-aes256-gcm-cipher oc-aes128-gcm-cipher \
	test-config-per-group ac-aes128-gcm-cipher ac-aes256-gcm-cipher \
	no-dtls-cipher psk-negotiate psk-negotiate-match
endif

if RADIUS_ENABLED
dist_check_SCRIPTS += radius radius-config
endif
endif


if HAVE_CWRAP
if HAVE_CWRAP_ALL
dist_check_SCRIPTS += test-vhost
endif

dist_check_SCRIPTS += test-pass test-pass-cert test-cert test-group-pass \
	test-pass-group-cert test-pass-group-cert-no-pass test-sighup \
	test-enc-key test-sighup-key-change test-get-cert test-san-cert \
	test-gssapi test-pass-opt-cert test-cert-opt-pass test-gssapi-opt-pass \
	test-gssapi-opt-cert haproxy-auth test-maintenance \
	test-group-name no-route-default no-route-group

if HAVE_CWRAP_PAM
dist_check_SCRIPTS += test-pam test-pam-noauth

if ENABLE_KERBEROS_TESTS
dist_check_SCRIPTS += kerberos
endif
endif

if HAVE_LIBOATH
dist_check_SCRIPTS += test-otp-cert test-otp
endif

endif


AM_CPPFLAGS += \
	$(LIBOPTS_CFLAGS) \
	$(LIBTALLOC_CFLAGS) \
	$(CODE_COVERAGE_CFLAGS) \
	-I$(top_srcdir)/src/ \
	-I$(top_builddir)/src/ \
	-I$(top_srcdir)/src/common/ \
	-I$(top_builddir)/src/common/ \
	-I$(top_srcdir)/gl/ \
	-I$(top_builddir)/gl/ \
	-I$(top_srcdir)/ \
	-I$(top_builddir)/

LDADD = ../gl/libgnu.a $(LIBTALLOC_LIBS) ../src/libccan.a $(CODE_COVERAGE_LDFLAGS)

kkdcp_parsing_SOURCES = kkdcp-parsing.c
kkdcp_parsing_LDADD = $(LDADD)

cstp_recv_SOURCES = cstp-recv.c
cstp_recv_CFLAGS = $(CFLAGS) $(LIBGNUTLS_CFLAGS) $(LIBTALLOC_CFLAGS)
cstp_recv_LDADD = $(LDADD) $(LIBGNUTLS_LIBS)

json_escape_SOURCES = json-escape.c
json_escape_LDADD = $(LDADD)

url_escape_SOURCES = url-escape.c
url_escape_LDADD = $(LDADD)

html_escape_SOURCES = html-escape.c
html_escape_LDADD = $(LDADD)

ipv4_prefix_SOURCES = ipv4-prefix.c
ipv4_prefix_LDADD = $(LDADD)

ban_ips_CPPFLAGS = $(AM_CPPFLAGS) -DUNDER_TEST
ban_ips_SOURCES = ban-ips.c
ban_ips_LDADD = $(LDADD)

str_test_SOURCES = str-test.c
str_test_LDADD = $(LDADD)

str_test2_SOURCES = str-test2.c
str_test2_LDADD = $(LDADD)

ipv6_prefix_SOURCES = ipv6-prefix.c
ipv6_prefix_LDADD = $(LDADD)

human_addr_CPPFLAGS = $(AM_CPPFLAGS)
human_addr_SOURCES = human_addr.c
human_addr_LDADD = $(LDADD)


valid_hostname_LDADD = $(LDADD)

port_parsing_LDADD = $(LDADD)

check_PROGRAMS = str-test str-test2 ipv4-prefix ipv6-prefix kkdcp-parsing json-escape ban-ips \
	port-parsing human_addr valid-hostname url-escape html-escape cstp-recv \
	proxyproto-v1

gen_oidc_test_data_CPPFLAGS = $(AM_CPPFLAGS) 
gen_oidc_test_data_SOURCES = generate_oidc_test_data.c
gen_oidc_test_data_LDADD = $(LDADD) $(CJOSE_LIBS) $(JANSSON_LIBS)

if ENABLE_OIDC_AUTH_TESTS
check_PROGRAMS += gen_oidc_test_data
dist_check_SCRIPTS += test-oidc
endif

TESTS =  $(check_PROGRAMS) $(dist_check_SCRIPTS) $(xfail_scripts)

XFAIL_TESTS = $(xfail_scripts)

TESTS_ENVIRONMENT = srcdir="$(srcdir)" \
	top_builddir="$(top_builddir)"

