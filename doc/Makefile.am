EXTRA_DIST = design.dia sample.config scripts/ocserv-up scripts/ocserv-down

dist_man_MANS = ocserv.8

ocserv.8: ../src/ocserv-args.def
	-sed 's/@subheading \(.*\)/@*\n@var{\1}\n@*/' $< > "$<".tmp && \
	@AUTOGEN@ -DMAN_SECTION=8 -Tagman-cmd.tpl "$<".tmp && \
	rm -f "$<".tmp
