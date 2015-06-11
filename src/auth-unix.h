int get_user_auth_group(const char *username, const char *suggested,
			char *groupname, int groupname_size);
void unix_group_list(void *pool, unsigned gid_min, char ***groupname, unsigned *groupname_size);
