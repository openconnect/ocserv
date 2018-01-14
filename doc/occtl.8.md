# occtl(8) -- OpenConnect VPN server control tool


## SYNOPSIS

**occtl** ['COMMAND']


## DESCRIPTION

This a control tool that can be used to send commands to ocserv. When
called without any arguments the tool can be used interactively, where 
each command is entered on a command prompt; alternatively the tool
can be called with the command specified as parameter. In the latter
case the tool's exit code will reflect the successful execution of
the command.

## OPTIONS

  * **-s, --socket-file**=_FILE_:
    Specify the server's occtl socket file.
    This option is only needed if you have multiple servers.

  * **-j, --json**:
    Output will be JSON formatted. This option can only be used with  non-interactive  output,
    e.g.,  'occtl  --json show users'.

  * **-n, --no-pager**:
    No pager will be used over output data.

  * **--debug**:
    Provide more verbose information in some commands.

  * **-h, --help**:
    Display usage information and exit.

  * **-v, --version**:
    Output version of program and exit.

## IMPLEMENTATION NOTES
This tool uses unix domain sockets to connect to ocserv.


## EXAMPLES
The tool can be run interactively when run with no arguments. When arguments are given they are
interpreted as commands. For example:

```
$ occtl show users
```

Any command line arguments to be used as options must precede the command (if any), as shown
below.

```
$ occtl --json show users
```

## Exit status

  * **0**:
    Successful program execution.

  * **1**:
    The operation failed or the command syntax was not valid.


## SEE ALSO

ocserv(8), ocpasswd(8)

## COPYRIGHT
Copyright (C) 2013-2017 Nikos Mavrogiannopoulos and others, all rights reserved.
This program is released under the terms of the GNU General Public License, version 2.

## AUTHORS

Written by Nikos Mavrogiannopoulos. Many people have
contributed to it.
