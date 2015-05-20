#
#  signing-milter - utils/Makefile
#  Copyright (C) 2010,2011  Andreas Schulze
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

all: utils.a

utils.a: append2buffer.o bio2file.o break_after_semicolon.o delete_marked_headers.o \
         dict_cdb.o dump_mailflags.o dump_pkcs7flags.o headerchain2signingbuffer.o get_num_semicolons.o \
         hdrdup.o is_already_signed.o is_multipart_mime.o linkedlist.o \
         load_pem.o logmsg.o lowercase.o node.o separate_header.o \
         validate_pem_permissions.o usage.o
	$(AR) rv utils.a $?

clean:
	rm -f *.o *.a

.c.o:
	@rm -f $@
	$(CC) $(CFLAGS) -c $*.c
