#ifndef COMMON_H
# define COMMON_H
ssize_t force_write(int sockfd, const void *buf, size_t len);
ssize_t force_read(int sockfd, void *buf, size_t len);
int ip_cmp(const struct sockaddr_storage *s1, const struct sockaddr_storage *s2, size_t n);

#endif

