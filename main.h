#ifndef _MAIN_H_INCLUDED_
#define _MAIN_H_INCLUDED_

#include <grp.h>
#include <pwd.h>
#include <openssl/err.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sysexits.h>
#include <unistd.h>

#include "signing-milter.h"

#include "callbacks.h"
#include "main.h"
#include "stats.h"
#include "utils/utils.h"

/* parameter for smfi_opensocket */
#define REMOVE_EXISTING_SOCKETS 1

#ifdef DMALLOC
#include <dmalloc.h>
#endif

int main(int argc, char** argv);
void sig_handler(int signal);

#endif
