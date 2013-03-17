#ifndef _BASE64_H
#define _BASE64_H

#define ERR_BASE64_BUFFER_TOO_SMALL             0x0010
#define ERR_BASE64_INVALID_CHARACTER            0x0012

/*
 *  Encode a buffer into base64 format
 *
 * Parameters:
 *   dst      destination buffer
 *   dlen     size of the buffer (updated after call)
 *   src      source buffer
 *   slen     amount of data to be encoded
 *   flag     1 -- with delimiter ";"
 *            0 -- without delimiter
 * Return         0 if successful, or ERR_BASE64_BUFFER_TOO_SMALL.
 *                *dlen is always updated to reflect to amount of
 *                data that was written (or would have been written)
 *
 * Note           Call this function with *dlen = 0 to obtain the
 *                required buffer size in *dlen
 */
int base64_encode(unsigned char *dst, int *dlen,
                  unsigned char *src, int  slen, int flag);

/**
 *    Decode a base64-formatted buffer
 *
 * Parameters:
 *   dst      destination buffer
 *   dlen     size of the buffer (updated after call)
 *   src      source buffer
 *   slen     amount of data to be decoded
 *
 * Return         0 if successful, ERR_BASE64_BUFFER_TOO_SMALL, or
 *                ERR_BASE64_INVALID_DATA if an invalid char is found.
 *                *dlen is always updated to reflect to amount of
 *                data that was written (or would have been written)
 *
 * Note           Call this function with *dlen = 0 to obtain the
 *                required buffer size in *dlen
 */
int base64_decode(unsigned char *dst, int *dlen,
                  unsigned char *src, int  slen);

#endif /* base64.h */
