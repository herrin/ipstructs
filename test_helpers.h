/* test_helpers.h
 *
 * contains shared functions used by the test modules
 */

#include <stdio.h>
#include <stdint.h>

/*#include "core/ubiq_mbuf.h"*/

/* hex_to_binary()
 *
 * Converts a hexidecimal string to a raw bytes in a buffer
 *
 * Input:
 *   hex: the string containing hexidecimal
 *   outbuffer: a buffer in which to place the raw bytes
 *   maxlen: maximum size of outbuffer
 *
 * Output:
 *   number of bytes placed in outbuffer or 0 on failure
 */
uint16_t
hex_to_binary(const char *hex, uint8_t *outbuffer, uint16_t maxlen);

/* make_packet_from_hex()
 *
 * Create a ubiq_mbuf from a packet represented as a hexidecimal string,
 * such as the output of tcpdump -e -XX 
 *
 * Input:
 *   hex: the string containing hexidecimal
 *
 * Output:
 *   A ubiq_mbuf malloced with rte_zmalloc() or NULL on failure
 */
/*struct ubiq_mbuf *
make_packet_from_hex(const char *hex);
*/

