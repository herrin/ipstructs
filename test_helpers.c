/* test_helpers.c
 *
 * contains shared functions used by the test modules
 */

#include <stdio.h>
#include <stdint.h>
#include <rte_malloc.h>

/*#include "config/ubiq_customer_resources_definitions.h"
#include "config/ubiq_addr.h"
#include "utils/test_helpers.h"
#include "utils/unit_test.h"*/


uint16_t
hex_to_binary(const char *hex, uint8_t *outbuffer, uint16_t maxlen)
{
    const char *hextoint =
    /*           1         2         3         4         5         6    */
    /* 0123456789012345678901234567890123456789012345678901234567890123 */
    /*                                  !"#$%&'()*+,-./0123456789:;<=>? */
      "          .  .                  .               abcdefghij      "
    /* @ABCDEFGHIJKLMNOPQRSTUVWXYZ[ ]^_`abcdefghijklmnopqrstuvwxyz{|}~  */
      " klmnop                          klmnop                         "
      "                                                                "
      "                                                                ";
    if ((hex == NULL) || (outbuffer == NULL)) {
        return 0;
    }
    const uint8_t *unsigned_hex = (const uint8_t*) hex;
  
    uint8_t *outbuffermax = outbuffer + maxlen;
    uint8_t *thisbyte = outbuffer;
    char priornibble;
    char havenibble = 0;
    while (*unsigned_hex) {
       char nibble = hextoint[*unsigned_hex];
       if (nibble == ' ') { // invalid
           return 0;
       }
       unsigned_hex++;
       if (nibble == '.') { // whitespace
           continue;
       }
       nibble -= 'a';
       if (havenibble) {
           havenibble = 0;
           *thisbyte = (((uint8_t) priornibble)<<4) | ((uint8_t) nibble);
           thisbyte++;
           if (thisbyte>=outbuffermax) {
               return 0;
           }
           continue; 
       }
       priornibble = nibble;
       havenibble = 1;
    }
    if (havenibble) { // not an even number of hex digits
       return 0;
    }
    return (uint16_t) (thisbyte-outbuffer);
}

/*
struct rte_mbuf *
make_packet_from_hex(const char *hex)
{
    struct rte_mbuf *mbuf = rte_zmalloc(NULL, sizeof(struct rte_mbuf) 
        + RTE_PKTMBUF_HEADROOM + 2048, 0);
    if (!mbuf) {
        return NULL;
    }

    // Make it single segment
    mbuf->next = NULL;
    mbuf->nb_segs = 1;
    // Set buffer address: offset = mbuf pointer + rte_mbuf size + Headroom
    mbuf->buf_addr = ((uint8_t *) mbuf) + sizeof(struct rte_mbuf) 
        + RTE_PKTMBUF_HEADROOM;
    mbuf->data_len = hex_to_binary(hex, mbuf->buf_addr, 2048);
    if (!mbuf->data_len) {
        rte_free(mbuf);
        return NULL;
    }
    mbuf->pkt_len = mbuf->data_len;

    // Standard MBUF components
    mbuf->port = 0;
    
    return ubiq_mbuf_transform_rte_mbuf(mbuf);
}
*/
