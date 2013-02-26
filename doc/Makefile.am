EXTRA_DIST = design.dia sample.config scripts/ocserv-up scripts/ocserv-down

dist_man_MANS = ocserv.1

ocserv.1: ../src/ocserv-args.def
	-sed 's/@subheading \(.*\)/@*\n@var{\1}\n@*/' $< > "$<".tmp && \
	@AUTOGEN@ -DMAN_SECTION=1 -Tagman-cmd.tpl "$<".tmp && \
	rm -f "$<".tmp
