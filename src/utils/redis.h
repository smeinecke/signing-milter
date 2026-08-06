#ifndef _REDIS_H_INCLUDED_
#define _REDIS_H_INCLUDED_

#include <stddef.h>

/*
 * Initialize the Redis lookup subsystem.
 * Called once from main() before the milter starts.
 * Returns 0 on success, -1 on error.
 */
extern int redis_global_init(void);

/*
 * Cleanup the Redis lookup subsystem.
 * Called once from main() at shutdown.
 */
extern void redis_global_cleanup(void);

/*
 * Look up a sender address in Redis.
 *
 * The address is normalized (strip <> and lowercased) inside this function.
 * On success (return 0), *pem is set to a freshly allocated PEM cert+key string
 * and *chain is set to a freshly allocated chain string or NULL. The caller
 * owns the returned memory and must free it.
 *
 * Returns:
 *   0  - certificate data found
 *   1  - key/cert not found (not a Redis error)
 *  -1  - Redis connection/protocol error
 */
extern int redis_lookup_cert(const char* raw_address,
                             char** pem, size_t* pem_len,
                             char** chain, size_t* chain_len);

#endif
