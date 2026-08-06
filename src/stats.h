#ifndef _STATS_H_INCLUDED_
#define _STATS_H_INCLUDED_

#include <assert.h>
#include <pthread.h>
#include <sys/time.h>

#include "utils/utils.h"

void init_stats(void);
void reset_stats(void);
void inc_stats(const struct timeval *duration);
int get_signed_mails(void);
void get_signing_time(struct timeval *duration_total);
void output_stats(void);

#endif
