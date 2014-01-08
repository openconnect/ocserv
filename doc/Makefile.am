EXTRA_DIST = design.dia sample.config scripts/ocserv-script sample.passwd \
	systemd/ocserv.service systemd/ocserv.socket \
	dbus/org.infradead.ocserv.conf

dist_man_MANS = ocserv.8 ocpasswd.8

ocserv.8: ../src/ocserv-args.def
	-sed 's/@subheading \(.*\)/@*\n@var{\1}\n@*/' $< > "$<".tmp && \
	@AUTOGEN@ -L../src -DMAN_SECTION=8 -Tagman-cmd.tpl "$<".tmp && \
	rm -f "$<".tmp

ocpasswd.8: ../src/ocpasswd-args.def
	-sed 's/@subheading \(.*\)/@*\n@var{\1}\n@*/' $< > "$<".tmp && \
	@AUTOGEN@ -L../src -DMAN_SECTION=8 -Tagman-cmd.tpl "$<".tmp && \
	rm -f "$<".tmp

install-data-local:
	test -d "$(DBUS_SERVICES_DIR)" && $(INSTALL_DATA) dbus/org.infradead.ocserv.service $(DBUS_SERVICES_DIR)
	test -d "$(DBUS_CONFIG_DIR)" && $(INSTALL_DATA) dbus/org.infradead.ocserv.conf $(DBUS_CONFIG_DIR)
	test -d "/usr/lib/systemd/system/" && $(INSTALL_DATA) systemd/ocserv.service /usr/lib/systemd/system/
	test -d "/usr/lib/systemd/system/" && $(INSTALL_DATA) systemd/ocserv.socket /usr/lib/systemd/system/
