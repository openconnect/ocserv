#ifndef SETPROCTITLE_H
# define SETPROCTITLE_H

void __attribute__ ((format(printf, 1, 2)))
setproctitle(const char *fmt, ...);

#endif
