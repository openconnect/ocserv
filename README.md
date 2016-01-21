[![build status](https://ci.gitlab.com/projects/7712/status.png?ref=master)](https://ci.gitlab.com/projects/7712?ref=master)

# About

This program is openconnect VPN server (ocserv), a server for the
[openconnect VPN client](http://www.infradead.org/openconnect/).
It follows the [openconnect protocol](https://github.com/openconnect/protocol)
and is believed to be compatible with CISCO's AnyConnect SSL VPN. 


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
OATH:         liboath-dev        / liboath-devel
Radius:       libradcli-dev      / radcli-devel
```

Dependencies for development, testing, or dependencies that can be skipped
in an embedded system (e.g., because a replacement library is included):

```
libprotobuf-c0-dev / protobuf-c-devel
libtalloc-dev      / libtalloc-devel
libhttp-parser-dev / http-parser-devel
libpcl1-dev        / pcllib-devel
libopts25-dev      / autogen-libopts-devel
autogen            / autogen
protobuf-c-compiler/ protobuf-c
gperf              / gperf
liblockfile-bin    / lockfile-progs
nuttcp             / nuttcp
                   / uid_wrapper
                   / socket_wrapper
                   / gssntlmssp
```

See [README-radius](doc/README-radius.md) for more information on Radius
dependencies and its configuration.

# Build instructions

To build from a distributed release use:

```
$ ./configure && make
```

When cross compiling it may be useful to add the --enable-local-libopts
option to configure.


To build from the git repository use:
```
$ autoreconf -fvi
$ ./configure && make
```

In addition to the prerequisites listed above, building from git requires
the following packages: autoconf, automake, autogen, git2cl, and xz.

Note that the system's autogen version must match the included libopts
version on the development system, if the included libopts library is to
be used.


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


# How the VPN works

Please see the [technical description page](http://www.infradead.org/ocserv/technical.html).

