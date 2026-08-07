#ifndef _UTILS_H_INCLUDED_
#define _UTILS_H_INCLUDED_

#include <cdb.h>
#include <libmilter/mfapi.h>
#include <openssl/ssl.h>
#include <syslog.h>

#include "../signing-milter.h"
#include "address.h"
#include "redis.h"

#define PHASE_PRE_SIGN	3
#define PHASE_POST_SIGN	2

extern int append2buffer(unsigned char** buf, size_t* buf_size, const char* data2append, size_t append_data_size);
extern int bio2file(BIO *b, const char* dir, const char* prefix, const char* queueid);
extern char* break_after_semicolon(char* string, int phase);
extern int delete_marked_headers(SMFICTX* ctx, CTXDATA* ctxdata);

extern void dict_open(const char* path, DICT* dict);
extern int  dict_reload(DICT* dict);
extern const char* dict_lookup(DICT* dict, const char* key);
extern void dict_close(DICT* dict);

extern void dump_mailflags(int flags);
extern void dump_pkcs7flags(int flags);
extern int get_num_semicolons(const char* string);
extern char* hdrdup(const char* string);
extern int headerchain2signingbuffer(SMFICTX* ctx, CTXDATA* ctxdata);
extern int is_already_signed(const char* headerf, const char* headerv);
extern int is_multipart_mime(const char* headerf, const char* headerv);

extern NODE* get_last(NODE* node);
extern NODE* appendnode(NODE** head, NODE* node);
extern NODE* deletenode(NODE* node);
extern void deletechain(NODE* node);

extern X509* load_pem_cert(int fd);
extern EVP_PKEY* load_pem_key(int fd, char* pass);
extern STACK_OF(X509)* load_pem_chain(int fd);

extern X509* load_pem_cert_mem(const char* data, size_t len);
extern EVP_PKEY* load_pem_key_mem(const char* data, size_t len, const char* pass);
extern STACK_OF(X509)* load_pem_chain_mem(const char* data, size_t len);

extern void logmsg(int priority, const char *fmt, ...);
extern char *lowercase(char *);

extern NODE* newnode(const char* headerf, const char* headerv, int phase);
extern void freenode(NODE* node);

extern char* separate_header(char* line, char** headerf);

extern void usage(void);
extern void version(void);
extern int open_and_validate_pem(const char* pemfilename, int optional);
extern int validate_pem_permissions(const char* pemfilename);

#endif
