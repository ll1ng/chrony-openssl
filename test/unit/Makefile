TEST_WRAPPER =
CHRONY_SRCDIR = ../..

CC = gcc
CFLAGS = -O2 -g -D_FORTIFY_SOURCE=2 -fPIE -fstack-protector-strong --param=ssp-buffer-size=4 -Wmissing-prototypes -Wall -pthread
CPPFLAGS = -I$(CHRONY_SRCDIR)   -I/usr/include/p11-kit-1
LDFLAGS =  -pie -Wl,-z,relro,-z,now  -lm -lnettle -lgnutls  -lcap -lseccomp

SHARED_OBJS = test.o

TEST_OBJS := $(sort $(patsubst %.c,%.o,$(wildcard *.c)))
TESTS := $(patsubst %.o,%.test,$(filter-out $(SHARED_OBJS),$(TEST_OBJS)))

CHRONYD_OBJS := $(patsubst %.o,$(CHRONY_SRCDIR)/%.o,$(filter-out main.o,\
		  $(filter %.o,$(shell $(MAKE) -f $(CHRONY_SRCDIR)/Makefile \
					print-chronyd-objects NODEPS=1))))

all: $(TESTS)

$(CHRONYD_OBJS): ;

%.test: %.o $(SHARED_OBJS) $(CHRONYD_OBJS)
	$(CC) $(CFLAGS) -o $@ $(filter-out $(CHRONY_SRCDIR)/$<,$^) $(LDFLAGS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $<

check: $(TESTS)
	@ret=0; \
	for t in $^; do \
	  $(TEST_WRAPPER) ./$$t || ret=1; \
	done; \
	exit $$ret

clean:
	rm -f *.o *.gcda *.gcno core.* $(TESTS)
	rm -rf .deps

distclean: clean
	rm -f Makefile

.deps:
	@mkdir .deps

.deps/%.d: %.c | .deps
	@$(CC) -MM $(CPPFLAGS) -MT '$(<:%.c=%.o) $@' $< -o $@

-include $(TEST_OBJS:%.o=.deps/%.d)
