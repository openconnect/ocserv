#ifndef OCCTL_H
# define OCCTL_H

#include <stdlib.h>
#include <time.h>

FILE* pager_start(void);
void pager_stop(FILE* fp);
void print_time_ival7(time_t t, FILE * fout);

#endif
