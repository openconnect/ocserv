#ifndef VASPRINTF_H
#define VASPRINTF_H
#include <config.h>
#include <string.h>

#ifndef HAVE_VASPRINTF

int _ocserv_vasprintf(char **strp, const char *fmt, va_list ap);
#define vasprintf _ocserv_vasprintf

#endif

#endif
