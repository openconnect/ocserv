# Intro

To enforce isolation between clients and with the authenticating process, 
ocserv consists of 3 components; the main process, the security module and
the worker processes. The following sections describe the purpose and tasks
assigned to each component, and the last section describes the communication
protocol between them.


# VPN overview

See https://ocserv.gitlab.io/www/technical.html


## The main process

The main component consists of the process which is tasked to:
 
 * Listen for incoming TCP connections and fork a new worker process
   to handle it. - See main.c

 * Listen for incomping UDP "connections" and forward the packet stream
   to the appropriate worker process. - See main.c

 * Create and forward to workers with an authenticated user a dedicated
   tun device. - See AUTH_COOKIE_REQ message handling.

 * Keep track of all connected users. - See the proc_st list in main.h

 * Execute any privileged operations that cannot be handled by worker
    processes (e.g., change the MTU in a tun device) - See main-misc.c

 * Execute any operations that require state for the worker processes,
    e.g., store TLS session data for resumption - See main-misc.c


## The security module process

The security module component consists of a process which keeps all
sensitive data (e.g., private keys, PAM state), that should not be leaked to
a worker process. It is separate from main to ensure that no such data are
leaked during a fork(). It handles:

 * TLS authentication (i.e., private key decryption and signing). That is
   it operates as a 'software security module' for the worker processes to
   use the private key used for TLS without accessing it. - See
   SM_CMD_SIGN/DECRYPT message handling in sec-mod.c.

 * Username/password authentication. That is a worker process needs to
   communicate with the security module the client username/password and
   get a cookie (ticket) to be considered as logged in by the main process.
   The username/password authentication includes GSSAPI authentication.
   For this exchange see the SM_CMD_AUTH_* message handling.

 * Partial certificate authentication. A user certificate received by the
   worker process, is verified by it, and on its SM_CMD_AUTH_INIT message
   it indicates the verification status. The security module approves, 
   and performs any other authentication method necessary.

 * Gatekeeper for accounting information keeping and reporting. That is
   currently closely related to radius accounting. The security module
   receives periodically accounting data from the workers and forwards the
   data to the radius accounting server. See the SM_CMD_CLI_STATS message
   handling.

 * Gatekeeper for new user sessions. The security module assigns a session
   ID (SID) to all connecting users. When the main process receives a request
   to resume a session with a SID from a worker process, it will notify the
   security module which keeps the authentication state. The security module
   will return any additional user configuration settings (received via radius
   or per-user config file) - See SM_CMD_AUTH_SESSION_OPEN and SM_CMD_AUTH_SESSION_CLOSE
   message handling.

Currently it seems we require quite an amount of communication between the
main process and the security module. That may affect scaling. If that
occurs it may be possible to exec() the worker process, to ensure there
is no shared memory with main, and transfer some of the sec-mod tasks
directly to main (e.g., accounting information, and remove SESSION_OPEN
and SESSION_CLOSE messages).


## The worker processes

The worker processes perform the TLS handshake, and HTTP exchange for
authentication. After that they simply act as bridge between the tun
device and the client. The tasks handled are:

 * TLS authentication. Perform the TLS key exchange, and when needed verify
   the client certificate.

 * Bridge user authentication with the security module.

 * Forward the cookie received by the security module to main to obtain a
   tun device.

 * Establish a DTLS channel. When a client initiates a UDP session with
   main, that session is connected and forwarded to the worker. The worker
   establishes a DTLS channel over that.

 * Bridge the tun device with the TLS and DTLS channels.


## IPC Communication

* Authentication

``` 
  main                 sec-mod                 worker
   |                       |                      |
   |                       |  <--SEC_AUTH_INIT--- |
   |                       |  ---SEC_AUTH_REPLY-> |
   |                       |  <--SEC_AUTH_CONT--- |
   |                       |         .            |
   |                       |         .            |
   |                       |         .            |
   |                       |  ---SEC_AUTH_REPLY-> |
   |                       |                      |
   | <----------AUTH_COOKIE_REQ------------------ |
   |                       |                      |
   | --SECM_SESSION_OPEN-> |                      |
   | <-SECM_SESSION_REPLY- |                      |   #contains additional config for client
   |                       |                      |
   | ---------------AUTH_COOKIE_REP-------------> |   #forwards the additional config for client
   |                       |                      |
   | <------------SESSION_INFO------------------- |
   |                       |                      |
   |                       | <-- SEC_CLI_STATS -- |
   |                       |            (disconnect)
   | -SECM_SESSION_CLOSE-> |
   | <---SECM_CLI_STATS--- |

```


* Auth in main process (cookie auth only)

```
   main                              worker
                      <------     AUTH_COOKIE_REQ
 AUTH_REP(OK/FAILED)  ------>
  +user config

```


## IPC Communication for SID assignment

This is the same diagram as above but shows how the session ID (SID)
is assigned and used throughout the server.

``` 
  main                  sec-mod                       worker
   |                       |                            |
   |                       |  <--SEC_AUTH_INIT---       |
   |                       |  -SEC_AUTH_REP (NEW SID)-> |
   |                       |  <--SEC_AUTH_CONT (SID)--- |
   |                       |         .                  |
   |                       |         .                  |
   |                       |         .                  |
   |                       |  ----SEC_AUTH_REP -------> |

(note that by that time the client/worker may be disconnected,
and reconnect later and use the cookie -SID- to resume the
already authenticated session).

   |                       |                            |
   | <----------AUTH_COOKIE_REQ (SID)-----------------  |
   |                       |                            |
   | -SESSION_OPEN (SID)-> |                            |
   | <--SESSION_REPLY----  |                            |   #contains additional config for client
   |                       |                            |
   | -----------------AUTH_REP----------------------->  |   #forwards the additional config for client
   |                       |                            |
   | <------------SESSION_INFO------------------------  |
   |                       |                            |
   |                       | <-- CLI_STATS (SID)------- |
   |                       |            (disconnect)
   | -SESSION_CLOSE(SID)-> |
   | <-- CLI_STATS (SID)-- |

```

## Cookies

Cookies are valid for the value configured in `cookie-timeout` option, after
a client disconnects due to timeout. Their purpose is to allow mobile clients to
roam between networks without significant disruption in the VPN service.

