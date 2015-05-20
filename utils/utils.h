/*
 * signing-milter - utils/utils.h
 * Copyright (C) 2010-2012  Andreas Schulze
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; only version 2 of the License is applicable.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Authors:
 *   Andreas Schulze <signing-milter at andreasschulze.de>
 *
 */

#ifndef _UTILS_H_INCLUDED_
#define _UTILS_H_INCLUDED_

#include <cdb.h>
#include <libmilter/mfapi.h>
#include <openssl/ssl.h>
#include <syslog.h>

#include "../signing-milter.h"

extern int append2buffer(unsigned char** buf, size_t* buf_size, char* data2append, size_t append_data_size);
extern int bio2file(BIO *b, const char* dir, const char* prefix, const char* queueid);
extern char* break_after_semicolon(char* string);
extern int delete_marked_headers(SMFICTX* ctx, CTXDATA* ctxdata);

extern void dict_open(const char* path, DICT* dict);
extern int warn_if_dict_changed(DICT* dict);
extern const char* dict_lookup(DICT* dict, const char* key);
extern void dict_close(DICT* dict);

extern void dump_mailflags(int flags);
extern void dump_pkcs7flags(int flags);
extern int get_num_semicolons(char* string);
extern char* hdrdup(const char* string);
extern int headerchain2signingbuffer(SMFICTX* ctx, CTXDATA* ctxdata);
extern int is_already_signed(char* headerf, char* headerv);
extern int is_multipart_mime(char* headerf, char* headerv);

extern NODE* get_last(NODE* node);
extern NODE* appendnode(NODE** head, NODE* node);
extern NODE* deletenode(NODE* node);
extern void deletechain(NODE* node);

extern X509* load_pem_cert(const char* file);
extern EVP_PKEY* load_pem_key(const char* file, const char* pass);
extern STACK_OF(X509)* load_pem_chain(const char* file);

extern void logmsg(int priority, const char *fmt, ...);
extern char *lowercase(char *);

extern NODE* newnode(char* headerf, char* headerv);
extern void dumpnode(FILE* stream, NODE* node, char* lineend);
extern void freenode(NODE* node);

extern char* separate_header(const char* line, char** headerf);

extern void usage(void);
extern void version(void);
extern int validate_pem_permissions(const char* pemfilename);

#endif
