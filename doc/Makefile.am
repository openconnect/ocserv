EXTRA_DIST = design.dia sample.config scripts/ocserv-script sample.passwd \
	systemd/socket-activated/ocserv.service  systemd/standalone/ocserv.service \
	systemd/socket-activated/ocserv.socket README-radius.md \
	profile.xml sample.otp DCO.txt

if !SKIP_MANPAGES

dist_man_MANS = ocserv.8 ocpasswd.8 occtl.8

ocserv.8: ocserv.8.md sample.config
	sed -e '/@CONFIGFILE@/{r sample.config.tmp' -e 'd}' <$< >ocserv.tmp
	ronn -r ocserv.tmp > $@

occtl.8: occtl.8.md
	ronn -r $^ > $@

ocpasswd.8: ocpasswd.8.md
	ronn -r $^ > $@

endif
