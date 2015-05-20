/*
 * signing-milter - stats.c
 * Copyright (C) 2010,2011  Andreas Schulze
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

#include "stats.h"

static pthread_mutex_t stats_lock;
static long unsigned int count;
static struct timeval totaltime;

void init_stats(void) {
    pthread_mutex_init(&stats_lock, NULL);
    count = 0;
    totaltime.tv_sec = 0;
    totaltime.tv_usec = 0;
}

void reset_stats(void) {
    pthread_mutex_lock(&stats_lock);
    count = 0;
    totaltime.tv_sec = 0;
    totaltime.tv_usec = 0;
    pthread_mutex_unlock(&stats_lock);
}

void inc_stats(const struct timeval *duration) {

    assert(duration != NULL);

    pthread_mutex_lock(&stats_lock);
    count++;
    totaltime.tv_sec += duration->tv_sec;
    totaltime.tv_usec += duration->tv_usec;
    if (totaltime.tv_usec >= 1000000) {
        totaltime.tv_usec -= 1000000;
        totaltime.tv_sec++;
    }
    pthread_mutex_unlock(&stats_lock);
}

int get_signed_mails(void) {

    int current_count;

    pthread_mutex_lock(&stats_lock);
    current_count = count;
    pthread_mutex_unlock(&stats_lock);

    return(current_count);
}

void get_signing_time(struct timeval *current_totaltime) {

    assert(current_totaltime != NULL);

    pthread_mutex_lock(&stats_lock);
    current_totaltime->tv_sec = totaltime.tv_sec;
    current_totaltime->tv_usec = totaltime.tv_usec;
    pthread_mutex_unlock(&stats_lock);
}

void output_stats(void) {

    struct timeval stats_totaltime;
    unsigned long int stats_count;

    get_signing_time(&stats_totaltime);
    stats_count = get_signed_mails();

    logmsg(LOG_NOTICE, "STATISTIK: %d/%d.%d", stats_count,
       stats_totaltime.tv_sec,stats_totaltime.tv_usec);
}
