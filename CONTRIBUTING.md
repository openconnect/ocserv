# ocserv -- Information about our contribution rules and coding style

 Anyone is welcome to contribute to ocserv. You can either take up
tasks from our [planned list](https://gitlab.com/ocserv/ocserv/milestones),
or suprise us with enhancement we didn't plan for. In all cases be prepared
to defend and justify your enhancements, and get through few rounds
of changes. 

We try to stick to the following rules, so when contributing please
try to follow them too.


## Git commits:

Note that when contributing code you will need to assert that the contribution is
in accordance to the "Developer's Certificate of Origin" as found in the 
file [DCO.txt](doc/DCO.txt).

To indicate that, make sure that your contributions (patches or merge requests),
contain a "Signed-off-by" line, with your real name and e-mail address. 
To automate the process use "git am -s" to produce patches and/or set the
a template to simplify this process, as follows.

```
$ echo "Signed-off-by: My Full Name <email@example.com>" > ~/.git-template
$ git config commit.template ~/.git-template
```


## Test suite:

   New functionality should be accompanied by a test case which verifies
the correctness of ocserv operation on successful use of the new
functionality, as well as on fail cases. The test suite is run on "make check"
on every system ocserv is installed, except for the tests/suite part
which is only run during development.

 ocserv relies on gitlab-ci which is configured in .gitlab-ci.yml
file in the repository. The goal is to have a test suite which runs for
every new merge request prior to merging. There are no particular rules for
the test targets, except for them being reliable and running in a reasonable
timeframe (~1 hour).


## Reviewing code

 Reviews are necessary for external contributions, and encouraged otherwise. A review,
is a way to prevent accidental mistakes, or design issues, as well as enforce this guide.
For example, verify that there is a reasonable test suite, and whether it covers
reasonably the new code, as well as check for obvious mistakes in the new code.

The intention is to keep reviews lightweight, and rely on CI for tasks such
as compiling and testing code and features.

[Guidelines to consider when reviewing.](https://github.com/thoughtbot/guides/tree/master/code-review)


## Gnulib / CCAN

The directory `gl/`, contains gnulib files. The directly `src/ccan` contains
libraries from the [CCAN project](https://github.com/rustyrussell/ccan),
both are used as collections of helper code.

To update to the latest gnulib sources you can run:
```
$ make gl
```

When considering a helper module check those projects; we have a mild
preference towards CCAN.


# Coding style

## C dialect:

  All code in ocserv is expected to conform to C99.


## Indentation style:

 In general, use [the Linux kernel coding style](https://www.kernel.org/doc/html/latest/process/coding-style.html).
You may indent the source using GNU indent, e.g. "indent -linux *.c".


## Commenting style

In general for documenting new code we prefer self-documented code to comments. That is:
  - Meaningful function and macro names
  - Short functions which do a single thing

That does not mean that no comments are allowed, but that when they are
used, they are used to document something that is not obvious, or the protocol
expectations.


## Header guards

  Each private C header file SHOULD have a header guard consisting of the
project name and the file path relative to the project directory, all uppercase.

Example: `src/main.h` uses the header guard `MAIN_H`.

The header guard is used as first and last effective code in a header file,
like e.g. in src/main.h:

```
#ifndef MAIN_H
#define MAIN_H

...

#endif /* MAIN_H */
```
