TARGET = eru_agent
OUTDIR = build/
CC = gcc

ifdef RELEASE
	CFLAGS = -Wall -O1
else
	CFLAGS = -ggdb -O0 
endif

# CFLAGS += -fPIC -march=pentium4 -DVER_SVNID=$(shell svn info | sed -n '/Revision/p' | awk '{ print $$2; }')  -std=gnu99
CFLAGS += -fPIC -march=core2 -DVER_SVNID=9  -std=gnu99 -D_GNU_SOURCE
	
LINKFLAGS = -Wl,-rpath,. -rdynamic
# LINKFLAGS = -Wl,-rpath,. -shared -shared-libgcc

INCDIR = -I../ -I./
LIBDIR = 

INCFILES = $(wildcard *.h)
SRCFILES = $(wildcard *.c)
OBJFILES = $(patsubst %.c,$(OUTDIR)%.o,$(SRCFILES))

LIBRARYS = -lpthread -lz

all: $(OUTDIR) $(TARGET)
	@echo 'End compiling. $(shell date +"%F %T")'

$(OUTDIR):
	[ -d $(OUTDIR) ] || mkdir $(OUTDIR)

$(OUTDIR)%.o: %.c $(INCFILES)
	$(CC) $(CFLAGS) $(INCDIR) -c $< -o $@

$(TARGET): $(OBJFILES)
	$(CC) $(LINKFLAGS) $(OBJFILES) $(LIBRARYS) -o $@

clean:
	@rm -rf $(OBJFILES) $(TARGET)


