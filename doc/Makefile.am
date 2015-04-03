EXTRA_DIST = design.dia sample.config scripts/ocserv-script sample.passwd \
	systemd/socket-activated/ocserv.service  systemd/standalone/ocserv.service \
	systemd/socket-activated/ocserv.socket README.radius \
	dbus/org.infradead.ocserv.conf profile.xml

dist_man_MANS = ocserv.8 ocpasswd.8 occtl.8

ocserv.8: ../src/ocserv-args.def
	-sed 's/@subheading \(.*\)/@*\n@var{\1}\n@*/' $< > "$<".tmp && \
	@AUTOGEN@ -L../src -DMAN_SECTION=8 -Tagman-cmd.tpl "$<".tmp && \
	rm -f "$<".tmp

occtl.8: ../src/occtl-args.def
	-sed 's/@subheading \(.*\)/@*\n@var{\1}\n@*/' $< > "$<".tmp && \
	@AUTOGEN@ -L../src -DMAN_SECTION=8 -Tagman-cmd.tpl "$<".tmp && \
	rm -f "$<".tmp

ocpasswd.8: ../src/ocpasswd-args.def
	-sed 's/@subheading \(.*\)/@*\n@var{\1}\n@*/' $< > "$<".tmp && \
	@AUTOGEN@ -L../src -DMAN_SECTION=8 -Tagman-cmd.tpl "$<".tmp && \
	rm -f "$<".tmp

if HAVE_DBUS

install-data-local:
	-test -d "$(DBUS_CONFIG_DIR)" && ! test -f $(DBUS_CONFIG_DIR)/org.infradead.ocserv.conf && $(INSTALL_DATA) dbus/org.infradead.ocserv.conf $(DBUS_CONFIG_DIR)

endif
