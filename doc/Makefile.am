EXTRA_DIST = design.dia sample.config scripts/ocserv-script sample.passwd \
	systemd/socket-activated/ocserv.service  systemd/standalone/ocserv.service \
	systemd/socket-activated/ocserv.socket README-radius.md \
	profile.xml sample.otp DCO.txt ocserv.8.md ocpasswd.8.md occtl.8.md

dist_man_MANS = ocserv.8 ocpasswd.8 occtl.8

if SKIP_MANPAGES

ocserv.8:
	touch $@

occtl.8:
	touch $@

ocpasswd.8:
	touch $@

else

ocserv.8: ocserv.8.md sample.config
	sed -e '/@CONFIGFILE@/{r sample.config' -e 'd}' <$< >ocserv.tmp
	ronn --pipe -r ocserv.tmp > $@.tmp
	test -s $@.tmp && mv $@.tmp $@

occtl.8: occtl.8.md
	ronn --pipe -r $^ > $@.tmp
	test -s $@.tmp && mv $@.tmp $@

ocpasswd.8: ocpasswd.8.md
	ronn --pipe -r $^ > $@.tmp
	test -s $@.tmp && mv $@.tmp $@

endif
