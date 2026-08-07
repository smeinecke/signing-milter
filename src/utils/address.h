#ifndef _ADDRESS_H_INCLUDED_
#define _ADDRESS_H_INCLUDED_

#include <stddef.h>

/*
 * Normalize an email-style identity for lookup/comparison.
 * Strips a surrounding pair of angle brackets and lowercases the result.
 * An empty or "<>" input is normalized to "<>".
 *
 * This version silently truncates overlong inputs.  It is appropriate for
 * non-security lookups such as signing-table certificate selection.
 */
extern void normalize_address(const char* raw, char* out, size_t out_len);

/*
 * Same normalization as normalize_address(), but fails closed: returns 0
 * (and sets *out to '\0' if out_len > 0) if the input does not fit into the
 * output buffer or cannot be represented safely.  Use this for authorization
 * decisions where truncation would allow two distinct identities to collide.
 */
extern int normalize_address_safe(const char* raw, char* out, size_t out_len);

#endif
