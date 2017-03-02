# This makefile supports different OS and CPU setups.
# You should use it this way :
#   make TARGET=os CPU=cpu

VERSION := 1.7.3

# Select target OS. TARGET must match a system for which COPTS and LIBS are
# correctly defined below.
TARGET = linux26s
#TARGET = linux26
#TARGET = linux24
#TARGET = linux24e
#TARGET = linux22
#TARGET = solaris

# pass CPU=<cpu_name> to make to optimize for a particular CPU
CPU = generic
#CPU = i586
#CPU = i686
#CPU = ultrasparc

# tools options
CC = gcc
LD = gcc

# This is for recent Linux 2.6 with splice and accept4()
COPTS.linux26s = -DENABLE_POLL -DENABLE_EPOLL -DENABLE_SPLICE -DENABLE_ACCEPT4
LIBS.linux26s =

# This is for standard Linux 2.6 with epoll()
COPTS.linux26 = -DENABLE_POLL -DENABLE_EPOLL
LIBS.linux26 =

# This is for enhanced Linux 2.4 with epoll() patch.
# Warning! If kernel is 2.4 with epoll-lt <= 0.21, then you must add
# -DEPOLL_CTL_MOD_WORKAROUND to workaround a very rare bug.
#COPTS.linux24e = -DENABLE_POLL -DENABLE_EPOLL -DUSE_MY_EPOLL -DEPOLL_CTL_MOD_WORKAROUND
COPTS.linux24e = -DENABLE_POLL -DENABLE_EPOLL -DUSE_MY_EPOLL
LIBS.linux24e =

# This is for standard Linux 2.4 without epoll()
COPTS.linux24 = -DENABLE_POLL
LIBS.linux24 =

# This is for Linux 2.2
COPTS.linux22 = -DUSE_GETSOCKNAME -DENABLE_POLL
LIBS.linux22 =

# This is for Solaris 8
COPTS.solaris = -fomit-frame-pointer -DENABLE_POLL -DFD_SETSIZE=65536
LIBS.solaris = -lnsl -lsocket

# CPU dependant optimizations
COPTS.generic = -O2
COPTS.i586 = -O2 -march=i586
COPTS.i686 = -O2 -march=i686
COPTS.ultrasparc = -O6 -mcpu=v9 -mtune=ultrasparc

# options for standard library
COPTS.libc=
LIBS.libc=

# you can enable debug arguments with "DEBUG=-g" or disable them with "DEBUG="
#DEBUG = -g -DDEBUG_MEMORY -DDEBUG_FULL
DEBUG = -g

# if small memory footprint is required, you can reduce the buffer size. There
# are 2 buffers per concurrent session, so 16 kB buffers will eat 32 MB memory
# with 1000 concurrent sessions. Putting it slightly lower than a page size
# will avoid the additionnal paramters to overflow a page. 8030 bytes is
# exactly 5.5 TCP segments of 1460 bytes.
#SMALL_OPTS = -DBUFSIZE=8030 -DMAXREWRITE=1030 -DSYSTEM_MAXCONN=1024
SMALL_OPTS =

# redefine this if you want to add some special PATH to include/libs
ADDINC =
ADDLIB =

# set some defines when needed.
# Known ones are -DENABLE_POLL, -DENABLE_EPOLL, and -DUSE_MY_EPOLL
# - use -DSTATTIME=0 to disable statistics, else specify an interval in
#   milliseconds.
DEFINE = -DSTATTIME=0

# global options
TARGET_OPTS=$(COPTS.$(TARGET))
CPU_OPTS=$(COPTS.$(CPU))

COPTS=-I. $(ADDINC) $(CPU_OPTS) $(TARGET_OPTS) $(SMALL_OPTS) $(DEFINE)
LIBS=$(LIBS.$(TARGET)) $(LIBS.libc) $(ADDLIB)

CFLAGS = -Wall $(COPTS) $(DEBUG)
LDFLAGS = -g

all: httpterm

httpterm: httpterm.o
	$(LD) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o:	%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.[oas] *~ *.rej core httpterm test nohup.out gmon.out
	rm -f httpterm-$(VERSION).tar.gz httpterm-$(VERSION)

tar:	clean
	ln -s . httpterm-$(VERSION)
	tar --exclude=httpterm-$(VERSION)/.git --exclude=httpterm-$(VERSION)/httpterm-$(VERSION).tar.gz --exclude=httpterm-$(VERSION)/httpterm-$(VERSION) -cf - httpterm-$(VERSION)/* | gzip -c9 >httpterm-$(VERSION).tar.gz
	rm -f httpterm-$(VERSION)

