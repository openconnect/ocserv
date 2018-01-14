# ocpasswd(8) -- OpenConnect server password utility

## SYNOPSIS
**ocpasswd** [--option-name[=value]] ['username']


## DESCRIPTION
This  program is openconnect password (ocpasswd) utility. It allows the generation
and handling of a 'plain' password file used by ocserv.

## OPTIONS

  * **-c, --passwd**=_FILE_::
    Specify the password file to use. Only useful when not using the default
    location.

  * **-g, --group**::
    Specify the user's group name.

  * **-d, --delete**::
    Deletes the specified user from the password file.

  * **-l, --lock**::
    Prevents the specified user from logging in by locking its password.

  * **-u, --unlock**::
    Re-enables login for the specified user by unlocking its password.

  * **-h, --help**::
    Display usage information and exit.

  * **-v, --version**::
    Output version of program and exit.

## FILES
The password format of ocpasswd is as follows.

```
username:groupname:encoded-password
```

The crypt(3) encoding is used for the encoded-password.

## EXAMPLES

### Adding a user

```
$ ocpasswd -c ocpasswd my_username
```

### Locking a user

```
$ ocpasswd -c ocpasswd -l my_username
```

### Unlocking a user

```
$ ocpasswd -c ocpasswd -u my_username
```

## Exit status

  * **0**:
    Successful program execution.

  * **1**:
    The operation failed or the command syntax was not valid.

## SEE ALSO

ocserv(8), occtl(8)

## COPYRIGHT
Copyright (C) 2013-2017 Nikos Mavrogiannopoulos and others, all rights reserved.
This program is released under the terms of the GNU General Public License, version 2.

## AUTHORS
Written by Nikos Mavrogiannopoulos. Many people have
contributed to it.

