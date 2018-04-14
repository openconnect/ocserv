[![Build status](https://gitlab.com/ocserv/ocserv/badges/master/build.svg)](https://gitlab.com/ocserv/ocserv/commits/master)
[![coverage report](https://gitlab.com/ocserv/ocserv/badges/master/coverage.svg)](https://ocserv.gitlab.io/ocserv/coverage/)

# About

This program is openconnect VPN server (ocserv), a server for the
[openconnect VPN client](http://www.infradead.org/openconnect/).
It follows the [openconnect protocol](https://github.com/openconnect/protocol)
and is believed to be compatible with CISCO's AnyConnect SSL VPN. 

The program consists of:
 1. ocserv, the main server application
 2. occtl, the server's control tool. A tool which allows one to query the
   server for information.
 3. ocpasswd, a tool to administer simple password files.


# Build dependencies

Required dependencies (Debian pkg/Fedora pkg):
```
libgnutls28-dev      / gnutls-devel
libev-dev            / libev-devel
```

Optional dependencies that enable specific functionality:
```
TCP wrappers: libwrap0-dev       / tcp_wrappers-devel
PAM:          libpam0g-dev       / pam-devel
LZ4:          liblz4-dev         / lz4-devel
seccomp:      libseccomp-dev     / libseccomp-devel
occtl:        libreadline-dev    / readline-devel
              libnl-route-3-dev  / libnl3-devel
GSSAPI:       libkrb5-dev        / krb5-devel
Radius:       libradcli-dev      / radcli-devel
```

Dependencies for development, testing, or dependencies that can be skipped
in an embedded system (e.g., because a replacement library is included):

```
libprotobuf-c0-dev / protobuf-c-devel
libtalloc-dev      / libtalloc-devel
libhttp-parser-dev / http-parser-devel
libpcl1-dev        / pcllib-devel
protobuf-c-compiler/ protobuf-c
gperf              / gperf
liblockfile-bin    / lockfile-progs
nuttcp             / nuttcp
lcov               / lcov
libuid-wrapper     / uid_wrapper
libpam-wrapper     / pam_wrapper
libnss-wrapper     / nss_wrapper
libsocket-wrapper  / socket_wrapper
gss-ntlmssp        / gssntlmssp
haproxy            / haproxy
iputils-ping       / iputils
```

See [README-radius](doc/README-radius.md) for more information on Radius
dependencies and its configuration.

# Build instructions

To build from a distributed release use:

```
$ ./configure && make && make check
```

To test the code coverage of the test suite use the following:
```
$ ./configure --enable-code-coverage
$ make && make check && make code-coverage-capture
```

Note that the code coverage reported does not currently include tests which
are run within docker.

In addition to the prerequisites listed above, building from git requires
the following packages: autoconf, automake, git2cl, and xz.

To build from the git repository use:
```
$ autoreconf -fvi
$ ./configure && make
```


# Basic installation instructions

Now you need to generate a certificate. E.g.
```
$ certtool --generate-privkey > ./test-key.pem
$ certtool --generate-self-signed --load-privkey test-key.pem --outfile test-cert.pem
```
(make sure you enable encryption or signing)

To run the server on the foreground edit the [sample.config](doc/sample.config) and then run:
```
# cd doc && ../src/ocserv -f -c sample.config
```

# Configuration

Several configuration instruction are available in [the recipes repository](https://github.com/openconnect/recipes).


# Profiling

If you use ocserv on a server with significant load and you'd like to help
improve it, you may help by sending profiling information. That includes
the bottlenecks in software, so future optimizations could be spent on the
real needs. 

In a Linux system you can profile ocserv using the following command.
```
# perf record -g ocserv
```

After the server is terminated, the output is placed in perf.data.
You may examine the output using:
```
# perf report
```


# Continuous Integration (CI)

We utilize the gitlab-ci continuous integration system. It is used to test
most of the Linux systems (see .gitlab-ci.yml),and is split in two phases,
build image creation and compilation/test. The build image creation is done
at the ocserv/build-images subproject and uploads the image at the gitlab.com
container registry. The compilation/test phase is on every commit to project.


# How the VPN works

Please see the [technical description page](http://ocserv.gitlab.io/www/technical.html).

