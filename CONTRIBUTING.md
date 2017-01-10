# ocserv -- Information about our contribution rules and coding style

 Anyone is welcome to contribute to ocserv. You can either take up
tasks from our [planned list](https://gitlab.com/ocserv/ocserv/milestones),
or suprise us with enhancement we didn't plan for. In all cases be prepared
to defend and justify your enhancements, and get through few rounds
of changes. 

We try to stick to the following rules, so when contributing please
try to follow them too.

# Git commits:

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

# Test suite:

   New functionality should be accompanied by a test case which verifies
the correctness of ocserv operation on successful use of the new
functionality, as well as on fail cases. The test suite is run on "make check"
on every system ocserv is installed, except for the tests/suite part
which is only run during development.

# C dialect:

  All code in ocserv is expected to conform to C99.


# Indentation style:

 In general, use the Linux kernel coding style.  You may indent the source
using GNU indent, e.g. "indent -linux *.c".


