ADOC = asciidoctor
ADOC_FLAGS =
SED = sed
HTML_TO_TXT = w3m -dump -T text/html

MAN_FILES = chrony.conf.man chronyc.man chronyd.man
TXT_FILES = faq.txt installation.txt
HTML_FILES = $(MAN_FILES:%.man=%.html) $(TXT_FILES:%.txt=%.html)
MAN_IN_FILES = $(MAN_FILES:%.man=%.man.in)

SYSCONFDIR = /etc
BINDIR = /usr/local/bin
SBINDIR = /usr/local/sbin
MANDIR = /usr/local/share/man
DOCDIR = /usr/local/share/doc/chrony
CHRONYRUNDIR = /var/run/chrony
CHRONYVARDIR = /var/lib/chrony
CHRONY_VERSION = 4.5
DEFAULT_USER = root
DEFAULT_HWCLOCK_FILE = 
DEFAULT_PID_FILE = /var/run/chrony/chronyd.pid
DEFAULT_RTC_DEVICE = /dev/rtc

SED_COMMANDS = "s%\@SYSCONFDIR\@%$(SYSCONFDIR)%g;\
	       s%\@BINDIR\@%$(BINDIR)%g;\
	       s%\@SBINDIR\@%$(SBINDIR)%g;\
	       s%\@CHRONY_VERSION\@%$(CHRONY_VERSION)%g;\
	       s%\@DEFAULT_HWCLOCK_FILE\@%$(DEFAULT_HWCLOCK_FILE)%g;\
	       s%\@DEFAULT_PID_FILE\@%$(DEFAULT_PID_FILE)%g;\
	       s%\@DEFAULT_RTC_DEVICE\@%$(DEFAULT_RTC_DEVICE)%g;\
	       s%\@DEFAULT_USER\@%$(DEFAULT_USER)%g;\
	       s%\@CHRONYRUNDIR\@%$(CHRONYRUNDIR)%g;\
	       s%\@CHRONYVARDIR\@%$(CHRONYVARDIR)%g;"

man: $(MAN_FILES) $(MAN_IN_FILES)
html: $(HTML_FILES)
txt: $(TXT_FILES)
docs: man html

%.html: %.adoc
	$(ADOC) $(ADOC_FLAGS) -b html -o - $< | $(SED) -e $(SED_COMMANDS) > $@

%.man.in: %.adoc
	$(ADOC) $(ADOC_FLAGS) -b manpage -o $@ $<

%.man: %.man.in
	$(SED) -e $(SED_COMMANDS) < $< > $@

%.txt: %.html
	$(HTML_TO_TXT) < $< > $@

install: $(MAN_FILES)
	[ -d $(DESTDIR)$(MANDIR)/man1 ] || mkdir -p $(DESTDIR)$(MANDIR)/man1
	[ -d $(DESTDIR)$(MANDIR)/man5 ] || mkdir -p $(DESTDIR)$(MANDIR)/man5
	[ -d $(DESTDIR)$(MANDIR)/man8 ] || mkdir -p $(DESTDIR)$(MANDIR)/man8
	cp chronyc.man $(DESTDIR)$(MANDIR)/man1/chronyc.1
	chmod 644 $(DESTDIR)$(MANDIR)/man1/chronyc.1
	cp chronyd.man $(DESTDIR)$(MANDIR)/man8/chronyd.8
	chmod 644 $(DESTDIR)$(MANDIR)/man8/chronyd.8
	cp chrony.conf.man $(DESTDIR)$(MANDIR)/man5/chrony.conf.5
	chmod 644 $(DESTDIR)$(MANDIR)/man5/chrony.conf.5

install-docs: $(HTML_FILES)
	[ -d $(DESTDIR)$(DOCDIR) ] || mkdir -p $(DESTDIR)$(DOCDIR)
	for f in $(HTML_FILES); do \
	  cp $$f $(DESTDIR)$(DOCDIR); \
	  chmod 644 $(DESTDIR)$(DOCDIR)/$$f; \
	done

clean:
	rm -f $(MAN_FILES) $(TXT_FILES) $(HTML_FILES)
	rm -f $(MAN_IN_FILES)

distclean:
	rm -f $(MAN_FILES) $(TXT_FILES) $(HTML_FILES)
	rm -f Makefile
