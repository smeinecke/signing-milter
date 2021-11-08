#
#  signing-milter - Makefile
#  Copyright (C) 2010-2019  Andreas Schulze
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; only version 2 of the License is applicable.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License along
#  with this program; if not, write to the Free Software Foundation, Inc.,
#  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
#  Authors:
#    Andreas Schulze <signing-milter at andreasschulze.de>
#
#

OBJ     = callbacks.o main.o stats.o
LIBS    = $(shell pkg-config --libs libcdb)
LIBS   += -lmilter
LIBS   += -lpthread
LIBS   += $(shell pkg-config --libs openssl)
CC      = gcc

all: signing-milter check

signing-milter: $(OBJ)
	$(MAKE) -C ctxdata/ CFLAGS="$(CFLAGS)" CPPFLAGS="$(CPPFLAGS)" CXXFFLAGS="$(CXXFLAGS)" all
	$(MAKE) -C utils/   CFLAGS="$(CFLAGS)" CPPFLAGS="$(CPPFLAGS)" CXXFFLAGS="$(CXXFLAGS)" all
	$(CC) $(CFLAGS) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) $(OBJ) ctxdata/ctxdata.a utils/utils.a $(LIBS) -o signing-milter

strip: signing-milter
	strip signing-milter

*.c:	config.h

.SILENT: config.h
config.h:
	test -f config.h || { \
	  echo "erstelle neue config.h"; \
	  echo '#ifndef _CONFIG_H_INCLUDED_' > $@  ; \
	  echo '#define _CONFIG_H_INCLUDED_' >> $@ ; \
	  echo '#define NDEBUG'              >> $@ ; \
	  echo '#endif'                      >> $@ ; \
	}

install: signing-milter
	install -d $(DESTDIR)/etc/cron.daily/
	install -d $(DESTDIR)/etc/cron.hourly/
	install -d $(DESTDIR)/etc/default/
	install -d $(DESTDIR)/etc/signing-milter/
	install -d $(DESTDIR)/usr/sbin/
	install -d $(DESTDIR)/usr/share/man/man8/
	install -d $(DESTDIR)/usr/share/signing-milter/
	install -d $(DESTDIR)/var/lib/supervise/signing-milter/
	install --mode 0755 signing-milter $(DESTDIR)/usr/sbin/
	install --mode 0644 signing-milter.8 $(DESTDIR)/usr/share/man/man8/
	install --mode 0644 debian/signing-milter.default $(DESTDIR)/etc/default/signing-milter
	install --mode 0755 run_signing-milter $(DESTDIR)/usr/share/signing-milter/
	install --mode 0755 debian/signing-milter.cron.daily $(DESTDIR)/etc/cron.daily/signing-milter
	install --mode 0755 debian/signing-milter.cron.hourly $(DESTDIR)/etc/cron.hourly/signing-milter
	ln -s ../../../../usr/share/signing-milter/run_signing-milter $(DESTDIR)/var/lib/supervise/signing-milter/run

clean:
	make -C ctxdata $@
	make -C utils $@
	rm -f config.h $(OBJ) signing-milter core*

.SILENT: check
.PHONY: check
check:
	egrep -r "strcpy|strcat|strtok|sprintf" *.c && echo "unsave function used" || true
