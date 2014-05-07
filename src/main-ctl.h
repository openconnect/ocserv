#ifndef MAIN_CTL_HANDLER_H
# define MAIN_CTL_HANDLER_H

#include <ctl.h>
        
int ctl_handler_init(main_server_st* s);
void ctl_handler_deinit(main_server_st* s);

int ctl_handler_set_fds(main_server_st* s, fd_set *rd_set, fd_set *wr_set);
void ctl_handler_run_pending(main_server_st* s, fd_set *rd_set, fd_set *wr_set);

#endif
