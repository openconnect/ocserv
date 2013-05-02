#ifndef DIE_H
# define DIE_H

# include <signal.h>

void kill_on_parent_kill(int sig);

sighandler_t ocsignal(int signum, sighandler_t handler);

#endif
