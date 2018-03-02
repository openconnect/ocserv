# ocserv(8) -- OpenConnect VPN server

## SYNOPSIS
**ocserv** [options] -c [config]

Openconnect VPN server (ocserv) is a VPN server compatible with the
openconnect VPN client. It follows the AnyConnect VPN protocol which 
is used by several CISCO routers.


## DESCRIPTION
This a standalone server that reads a configuration file (see below for more details),
and waits for client connections. Log messages are redirected to daemon facility.

The server maintains two connections/channels with the client. The main VPN 
channel is established over TCP, HTTP and TLS. This is the control channel as well 
as the backup data channel. After its establishment a UDP channel using DTLS 
is initiated which serves as the main data channel. If the UDP channel fails 
to establish or is temporarily unavailable the backup channel over TCP/TLS 
is being used.

This server supports multiple authentication methods,
including PAM and certificate authentication. Authenticated users are 
assigned an unprivileged worker process and obtain a networking (tun) device 
and an IP from a configurable pool of addresses.

Once authenticated, the server provides the client with an IP address and a list 
of routes that it may access. In order to allow high-speed transfers the 
server does not process or filter packets. It is expected that the server has 
or will set up any required routes or firewall rules. 

It is possible to separate users into groups, which are either present on their
certificate, or presented on login for the user to choose. That way a user may
take advantage of the different settings that may apply per group. See the 
comments on the configuration file for more information.

It is also possible to run hostname-based virtual servers which could support
different authentication methods. When multiple virtual servers are present
clients are distinguished by the advertised server name over TLS (SNI).
Clients which do not support or sent SNI, are directed to the default
server.

## OPTIONS

  * **-f, --foreground**::
    Do not fork server into background.

  * **-d, --debug**=_num_::
    Enable verbose network debugging information. _num_ must be between zero
    and 9999.

  * **-c, --config**=_FILE_::
    Specify the configuration file for the server.

  * **-t, --test-config**::
    Test the provided configuration file and exit. A successful exit error code
    indicates a valid configuration.

  * **-p, --pid-file**=_FILE_::
    Specify a PID file for the server.

  * **-h, --help**::
    Display usage information and exit.

  * **-v, --version**::
    Output version of program and exit.


## AUTHENTICATION
Users can be authenticated in multiple ways, which are explained in the following
paragraphs. Connected users can be managed using the _occtl_ tool.

### Password authentication

If your system supports Pluggable Authentication Modules (PAM), then
ocserv will take advantage of it to password authenticate its users.
Otherwise a plain password file similar to the UNIX password file is also supported.
In that case the 'ocpasswd' tool can be used for its management.
Note that password authentication can be used in conjunction with certificate 
authentication.

### GSSAPI authentication

ocserv will take advantage of the MIT Kerberos project GSSAPI libraries, and
allow authentication using any method GSSAPI supports. That is, mainly, Kerberos
authentication. That is often more useful to be combined with PAM or other
password authentication methods so that a fallback mechanism can be used when
GSSAPI fails (e.g., when the user doesn't already have a Kerberos ticket). The
GSSAPI authentication is implemented using SPNEGO over HTTP (RFC4559).

### Public key (certificate) authentication

Public key authentication allows the user to be authenticated
by the possession of the private key that corresponds to a known
to the server public key. That allows the usage of common smart
cards for user authentication.

In ocserv, a certificate authority (CA) is used to sign the client 
certificates. That certificate authority can be local, used only by the 
server to sign its user's known public keys which are then given to 
users in a form of certificates. That authority need also provide a CRL 
to allow the server to reject the revoked clients (see *ca-cert*, *crl*).

In certificate authentication each client presents a certificate and signs
data provided by the server, as part of TLS authentication, to prove his 
possession of the corresponding private key. 
The certificate need also contain user identifying information,
for example, the user ID of the client must be embedded in the certificate's 
Distinguished Name (DN), i.e., in the Common Name, or UID fields. For the 
server to read the name, the *cert-user-oid* configuration option 
must be set.

The following examples demonstrate how to use certtool from GnuTLS to
generate such CA.

### Generating the CA

```
$ certtool --generate-privkey --outfile ca-key.pem
$ cat << _EOF_ >ca.tmpl
cn = "VPN CA"
organization = "Big Corp"
serial = 1
expiration_days = -1
ca
signing_key
cert_signing_key
crl_signing_key
_EOF_

$ certtool --generate-self-signed --load-privkey ca-key.pem \
           --template ca.tmpl --outfile ca-cert.pem
```

### Generating a local server certificate

The following example generates the server key and certificate
pair. The key generated is an RSA one, but different types
can be used by specifying the 'ecdsa' or 'dsa' options to
certtool.

```
$ certtool --generate-privkey --outfile server-key.pem
$ cat << _EOF_ >server.tmpl
cn = "VPN server"
dns_name = "www.example.com"
dns_name = "vpn1.example.com"
#ip_address = "1.2.3.4"
organization = "MyCompany"
expiration_days = -1
signing_key
encryption_key #only if the generated key is an RSA one
tls_www_server
_EOF_
  
$ certtool --generate-certificate --load-privkey server-key.pem \
           --load-ca-certificate ca-cert.pem --load-ca-privkey ca-key.pem \
           --template server.tmpl --outfile server-cert.pem
```

From this point the clients need ca-cert.pem to be able to securely
connect to the server.

Note that it is a better practice to use two separate RSA keys, one
with the signing_key option and another with the encryption_key.

### Generating an external CA-signed server certificate

```
$ certtool --generate-privkey --outfile server-key.pem
$ cat << _EOF_ >server.tmpl
cn = "My server"
dns_name = "www.example.com"
organization = "MyCompany"
expiration_days = -1
signing_key
encryption_key #only if the generated key is an RSA one
tls_www_server
_EOF_
$ certtool --generate-request --load-privkey server-key.pem \
           --template server.tmpl --outfile server-cert.csr
```

At this point you need to provide the server-cert.csr to your CA,
and they will send you the server certificate.

### Generating the client certificates

Note that it is recommended to leave detailed personal information out of the
certificate as it is sent in clear during TLS authentication. The following
process generates a certificate and converts it to PKCS #12 that is protected
by a PIN and most clients are able to import (the 3DES cipher is used in
the example because it is supported by far more devices than
AES).

```
$ certtool --generate-privkey --outfile user-key.pem
$ cat << _EOF_ >user.tmpl
cn = "user"
unit = "admins"
expiration_days = 365
signing_key
tls_www_client
_EOF_
$ certtool --generate-certificate --load-privkey user-key.pem \
           --load-ca-certificate ca-cert.pem --load-ca-privkey ca-key.pem \
           --template user.tmpl --outfile user-cert.pem
  
$ certtool --to-p12 --load-privkey user-key.pem \
           --pkcs-cipher 3des-pkcs12 \
           --load-certificate user-cert.pem \
           --outfile user.p12 --outder
```

### Revoking a client certificate

To revoke the previous client certificate, i.e., preventing the user from
accessing the VPN resources prior to its certificate expiration, use:

```
$ cat << _EOF_ >crl.tmpl
crl_next_update = 365
crl_number = 1
_EOF_
$ cat user-cert.pem >>revoked.pem
$ certtool --generate-crl --load-ca-privkey ca-key.pem \
           --load-ca-certificate ca-cert.pem --load-certificate revoked.pem \
           --template crl.tmpl --outfile crl.pem
```

After that you may want to notify ocserv of the new CRL by using
the HUP signal, or wait for it to reload it.

When there are no revoked certificates an empty revocation list
should be generated as follows.

```
$ certtool --generate-crl --load-ca-privkey ca-key.pem \
           --load-ca-certificate ca-cert.pem \
           --template crl.tmpl --outfile crl.pem
```

## IMPLEMENTATION NOTES
Note that while this server utilizes privilege separation and all
authentication occurs on the security module, this does not apply for TLS client 
certificate authentication. That is due to TLS protocol limitation.


## NETWORKING CONSIDERATIONS
In certain setups, where a firewall may be blocking ICMP responses, setting the
MSS of TCP connections to MTU will eliminate the "black hole" connection issues.
See http://lartc.org/howto/lartc.cookbook.mtu-mss.html for instructions
to enable it on a Linux system.

## FILES

### ocserv's configuration file format
By default, if no other file is specified, ocserv looks for its configuration
file at _/etc/ocserv/ocserv.conf_. An example configuration file follows.

```
@CONFIGFILE@
```

## SEE ALSO

occtl(8), ocpasswd(8)

## COPYRIGHT
Copyright (C) 2013-2018 Nikos Mavrogiannopoulos and others, all rights reserved.
This program is released under the terms of the GNU General Public License, version 2.

## AUTHORS
Written by Nikos Mavrogiannopoulos. Many people have
contributed to it.

