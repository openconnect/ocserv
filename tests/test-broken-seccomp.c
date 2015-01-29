#include <stdlib.h>
#include <stdio.h>
#include <seccomp.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>

int main()
{
	scmp_filter_ctx ctx;
	fd_set rfds;
	int fd = open("/dev/null", O_RDONLY), ret;

	ctx = seccomp_init(SCMP_ACT_ERRNO(EPERM));
	assert(ctx != 0);

	assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(select), 0) == 0);

	/* to allow printing and exiting */
	assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 0) == 0);
	assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) == 0);
	assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0) == 0);
	assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0) == 0);

	assert (seccomp_load(ctx) == 0);

	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);

	ret = select(fd+1, &rfds, NULL, NULL, NULL);
	if (ret < 0) {
		fprintf(stderr, "select is blocked!\n");
		exit(1);
	}
	fprintf(stderr, "all ok\n");
	exit(0);
}
