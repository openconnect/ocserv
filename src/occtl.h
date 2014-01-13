#ifndef OCCTL_H
# define OCCTL_H

#include <stdlib.h>
#include <time.h>

FILE* pager_start(void);
void pager_stop(FILE* fp);
void print_time_ival7(time_t t, FILE * fout);
void print_iface_stats(const char *iface, time_t since, FILE * out);

char* search_for_id(unsigned idx, const char* match, int match_size);
char* search_for_user(unsigned idx, const char* match, int match_size);
void entries_add(const char* user, unsigned user_size, unsigned id);
void entries_clear(void);

#endif
