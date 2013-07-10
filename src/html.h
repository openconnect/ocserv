#ifndef OC_HTML_H
# define OC_HTML_H

char* unescape_html(const char *html, unsigned len, unsigned *out_len);
char *unescape_url(const char *url, unsigned len, unsigned *out_len);

#endif
