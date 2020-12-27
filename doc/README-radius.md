Using Radius with ocserv
========================

For radius support the [radcli library](http://radcli.github.io/radcli/)
is required. The minimum requirement is version 1.2.0. Alternatively
the freeradius-client library can be used (1.1.7 is the minimum
requirement), but not all radius features may be available.

radcli uses a configuration file to setup the
server configuration. That is typically found at:
/etc/radcli/radiusclient.conf
and is best to copy the default installed as radiusclient-ocserv.conf
and edit it accordingly.

The important options for ocserv usage are the following:
```
dictionary 	/etc/radcli/dictionary
servers         /etc/radcli/servers
```

The dictionary should contain at least the attributes shown below,
and the servers file should contain the radius server to use.

---
**NOTE**

Note, that ocserv since 1.0.0 does not provide the 'NAS-Port' attribute
to server. In the previous versions the NAS-Port value was corresponding
to the worker process ID (PID), which changed on client reconnect (e.g.,
due to roaming). That caused accounting problems, and as there is no
notion of ports in ocserv, it is no longer sent.
This breaks the default configuration of freeradius servers which
assumes that the NAS-Port is sent. To make ocserv authentication
and accounting work with freeradius, you must configure the server
not to account NAS-Port by removing the NAS-Port attribute from the
acct_unique section.
---

Ocserv configuration
====================

For authentication the following line should be enabled.
```
auth = "radius[config=/etc/radcli/radiusclient.conf,groupconfig=true]"
```

Check the ocserv manpage for the meaning of the various options
such as groupconfig.

To enable accounting, use
```
acct = "radius[config=/etc/radcli/radiusclient.conf]"
```

and modify the following option to the time (in
seconds), that accounting information should be reported.
```
stats-report-time = 360
```

That value will be overridden by Acct-Interim-Interval if sent
by the server.

Note that the accounting session is reported as terminated as soon as
possible when the user disconnects explicitly. When the disconnection
is due to timeout or other network reasons, the users have their connection
remain valid until the `cookie-timeout` value expires.


Dictionary
==========

Ocserv supports the following radious attributes.

```
#	Standard attributes
ATTRIBUTE	User-Name		1	string
ATTRIBUTE	Password		2	string
ATTRIBUTE	NAS-Port		5	integer
ATTRIBUTE	Framed-Protocol		7	integer
ATTRIBUTE	NAS-Identifier		32	string
ATTRIBUTE	Acct-Input-Octets	42	integer
ATTRIBUTE	Acct-Output-Octets	43	integer
ATTRIBUTE	Acct-Session-Id		44	string
ATTRIBUTE	Acct-Input-Gigawords	52	integer
ATTRIBUTE	Acct-Output-Gigawords	53	integer
ATTRIBUTE	Acct-Interim-Interval	85	integer
ATTRIBUTE	Connect-Info		77	string


###########################
#	IPv4 attributes   #
###########################

# sets local IPv4 address in link:
ATTRIBUTE	NAS-IP-Address		4	ipaddr
# sets remote IPv4 address in link:
ATTRIBUTE	Framed-IP-Address	8	ipaddr
ATTRIBUTE	Framed-IP-Netmask	9	ipaddr

# sets routes (quite a kludge as it requires to have
# a CIDR string)
ATTRIBUTE	Framed-Route		22	string

# Sets group name using format "OU=group1;group2"
# Note that this works only when groupconfig is set to
# true, and if the groups sent by the server are made known
# to ocserv, via the select-group variable.
ATTRIBUTE	Class			25	string

# sets DNS servers
VENDOR Microsoft 311

BEGIN-VENDOR Microsoft

ATTRIBUTE	MS-Primary-DNS-Server 	28 	ipaddr
ATTRIBUTE 	MS-Secondary-DNS-Server 29 	ipaddr

END-VENDOR Microsoft


############################
#	IPv6 attributes    #
############################

# sets local IPv6 address in link:
ATTRIBUTE	NAS-IPv6-Address	95	string

# sets remote IPv6 subnet in link:
ATTRIBUTE	Delegated-IPv6-Prefix	123	ipv6prefix

# sets remote IPv6 address in link:
ATTRIBUTE	Framed-IPv6-Address	168	ipv6addr

# sets DNS servers
ATTRIBUTE	DNS-Server-IPv6-Address	169	ipv6addr

# Sets IPv6 routes
ATTRIBUTE	Framed-IPv6-Prefix	97	ipv6prefix
ATTRIBUTE	Route-IPv6-Information	170	ipv6prefix
```
