#ifndef _ADDRESS_H_INCLUDED_
#define _ADDRESS_H_INCLUDED_

#include <stddef.h>

/*
 * Normalize an email-style identity for lookup/comparison.
 * Strips a surrounding pair of angle brackets and lowercases the result.
 * An empty or "<>" input is normalized to "<>".
 */
extern void normalize_address(const char* raw, char* out, size_t out_len);

#endif
