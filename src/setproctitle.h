#ifndef SETPROCTITLE_H
# define SETPROCTITLE_H

# include <config.h>

# ifndef HAVE_SETPROCTILE

void __attribute__ ((format(printf, 1, 2)))
setproctitle(const char *fmt, ...);

# else

#  include <sys/types.h>
#  include <unistd.h>

# endif

#endif
