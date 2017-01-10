EXTRA_DIST = design.dia sample.config scripts/ocserv-script sample.passwd \
	systemd/socket-activated/ocserv.service  systemd/standalone/ocserv.service \
	systemd/socket-activated/ocserv.socket README-radius.md \
	profile.xml sample.otp DCO.txt

dist_man_MANS = ocserv.8 ocpasswd.8 occtl.8

ocserv.8: ../src/ocserv-args.def
	-$(SED) 's/@subheading \(.*\)/@*\n@var{\1}\n@*/' $< > "$<".tmp && \
	@AUTOGEN@ -L../src -DMAN_SECTION=8 -Tagman-cmd.tpl "$<".tmp && \
	rm -f "$<".tmp

occtl.8: ../src/occtl/occtl-args.def
	-$(SED) 's/@subheading \(.*\)/@*\n@var{\1}\n@*/' $< > "$<".tmp && \
	@AUTOGEN@ -L../src -DMAN_SECTION=8 -Tagman-cmd.tpl "$<".tmp && \
	rm -f "$<".tmp

ocpasswd.8: ../src/ocpasswd/ocpasswd-args.def
	-$(SED) 's/@subheading \(.*\)/@*\n@var{\1}\n@*/' $< > "$<".tmp && \
	@AUTOGEN@ -L../src -DMAN_SECTION=8 -Tagman-cmd.tpl "$<".tmp && \
	rm -f "$<".tmp

