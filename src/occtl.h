#ifndef OCCTL_H
# define OCCTL_H

#include <stdlib.h>
#include <time.h>
#include "common.h"

#ifdef HAVE_ORIG_READLINE
# include <readline/readline.h>
# include <readline/history.h>
#else
# include <readline.h>
#endif

#define DATE_TIME_FMT "%Y-%m-%d %H:%M"

FILE* pager_start(void);
void pager_stop(FILE* fp);
void print_time_ival7(time_t t, FILE * fout);
void print_iface_stats(const char *iface, time_t since, FILE * out);

void
bytes2human(unsigned long bytes, char* output, unsigned output_size, const char* suffix);

char* search_for_id(unsigned idx, const char* match, int match_size);
char* search_for_user(unsigned idx, const char* match, int match_size);
void entries_add(void *pool, const char* user, unsigned user_size, unsigned id);
void entries_clear(void);

#define DEFAULT_TIMEOUT (10*1000)
#define NO_GROUP "(none)"
#define NO_USER "(none)"

#define ERR_SERVER_UNREACHABLE "could not send message; possibly insufficient permissions or server is offline.\n"

unsigned need_help(const char *arg);
unsigned check_cmd_help(const char *line);

#ifdef HAVE_DBUS
# include <dbus/dbus.h>
# define CONN_TYPE struct dbus_ctx
#else
# define CONN_TYPE struct unix_ctx
#endif

CONN_TYPE *conn_init(void *pool, const char *socket_file);
void conn_close(CONN_TYPE*);

int conn_prehandle(CONN_TYPE *ctx);
void conn_posthandle(CONN_TYPE *ctx);

typedef int (*cmd_func) (CONN_TYPE * conn, const char *arg);

int handle_status_cmd(CONN_TYPE * conn, const char *arg);
int handle_list_users_cmd(CONN_TYPE * conn, const char *arg);
int handle_show_user_cmd(CONN_TYPE * conn, const char *arg);
int handle_show_id_cmd(CONN_TYPE * conn, const char *arg);
int handle_disconnect_user_cmd(CONN_TYPE * conn, const char *arg);
int handle_disconnect_id_cmd(CONN_TYPE * conn, const char *arg);
int handle_reload_cmd(CONN_TYPE * conn, const char *arg);
int handle_stop_cmd(CONN_TYPE * conn, const char *arg);

#endif
