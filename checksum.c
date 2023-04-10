#include "test_helpers.h"
#include "addresses.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <rte_tcp.h>

uint16_t ipv4_cksum(struct ipv4_hdr *ip)
{
  uint16_t sum = rte_ipv4_cksum(ip);
  return (sum==0xffff)?0:sum;
}

uint16_t ipv4_tcp_cksum(struct ipv4_hdr *ip, void *tcp)
{ 
  uint16_t tsum = rte_ipv4_udptcp_cksum(ip, tcp);
  return (tsum==0xffff)?0:tsum;
}

uint16_t ipv4_udp_cksum(struct ipv4_hdr *ip, void *udp)
{ 
  uint16_t usum = rte_ipv4_udptcp_cksum(ip, udp);
  return (usum==0)?0xffff:usum;
}


uint16_t
checksum_incremental_32(
    uint16_t old_checksum,
    uint32_t old_value,
    uint32_t new_value)
{
    uint32_t new_checksum = (uint32_t) ((~old_checksum) & 0xffff);
    old_value = ~old_value;
    new_checksum += (old_value >> 16) + (old_value & 0xffff);
    new_checksum += (new_value >> 16) + (new_value & 0xffff);
    new_checksum = (new_checksum >> 16) + (new_checksum & 0xffff);
    new_checksum += (new_checksum >> 16);

    return (uint16_t) ((~new_checksum) & 0xffff);
}

// Incrementally update checksum when modifying a 32-bit value.
void checksum_update_incremental_32(uint16_t* checksum_cell,
                                    uint32_t* value_cell,
                                    uint32_t new_value)
{
  uint32_t sum;

  uint32_t old_value = ~rte_be_to_cpu_32(*value_cell);

  sum = ~rte_be_to_cpu_16(*checksum_cell) & 0xffff;
  sum += (old_value >> 16) + (old_value & 0xffff);
  sum += (new_value >> 16) + (new_value & 0xffff);
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);

  *checksum_cell = rte_cpu_to_be_16(~sum & 0xffff);
  *value_cell = rte_cpu_to_be_32(new_value);
}

// Incrementally update checksum when modifying a 32-bit value.
void checksum_update_incremental_32b(uint16_t* checksum_cell,
                                    uint32_t* value_cell,
                                    uint32_t new_value)
{
  uint32_t sum;

  uint32_t old_value = ~(*value_cell);

  sum = ~(*checksum_cell) & 0xffff;
  sum += (old_value >> 16) + (old_value & 0xffff);
  sum += (new_value >> 16) + (new_value & 0xffff);
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);

  *checksum_cell = (~sum & 0xffff);
  *value_cell = (new_value);
}

// Incrementally update checksum when modifying a 16-bit value.
void checksum_update_incremental_16(uint16_t* checksum_cell,
                                    uint16_t* value_cell,
                                    uint16_t new_value)
{
  uint32_t sum;

  sum = ~ntohs(*checksum_cell) & 0xffff;
  sum += (~ntohs(*value_cell) & 0xffff) + new_value;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);

  *checksum_cell = htons(~sum & 0xffff);
  *value_cell = htons(new_value);
}

uint16_t
checksum_incremental_16(
    uint16_t old_checksum,
    uint16_t old_value,
    uint16_t new_value)
{
  uint32_t new_checksum = (uint32_t) ((~old_checksum) & 0xffff);
  new_checksum += ((~old_value) & 0xffff) + new_value;
  new_checksum = (new_checksum >> 16) + (new_checksum & 0xffff);
  new_checksum += new_checksum >> 16;

  return (uint16_t) ((~new_checksum) & 0xffff);
}

/* tcpdump -e -vv -i eth3 -n -s 0 -XX tcp port 22 and host minoc.dirtside.com
 * 17:04:37.661603 70:db:98:39:19:bf > 44:1e:a1:44:70:3f,
 * ethertype IPv4 (0x0800), length 105: (tos 0x0, ttl 56, id 12221,
 * offset 0, flags [DF], proto TCP (6), length 91)
 * 199.33.225.196.22 > 198.244.105.7.49678: Flags [P.],
 * cksum 0xb6f5 (correct), seq 1:40, ack 1, win 217,
 * options [nop,nop,TS val 466648354 ecr 248269409], length 39
 *      0x0000:  441e a144 703f 70db 9839 19bf 0800 4500  D..Dp?p..9....E.
 *      0x0010:  005b 2fbd 4000 3806 39fe c721 e1c4 c6f4  .[/.@.8.9..!....
 *      0x0020:  6907 0016 c20e 89aa 529c ab62 1357 8018  i.......R..b.W..
 *      0x0030:  00d9 b6f5 0000 0101 080a 1bd0 7d22 0ecc  ............}"..
 *      0x0040:  4a61 5353 482d 322e 302d 4f70 656e 5353  JaSSH-2.0-OpenSS
 *      0x0050:  485f 372e 3470 3120 4465 6269 616e 2d31  H_7.4p1.Debian-1
 *      0x0060:  302b 6465 6239 7534 0a                   0+deb9u4.
 */

void decrement_ttl (struct ipv4_header *ipv4)
{
        uint16_t *ttlptr = (uint16_t*) &(ipv4->time_to_live);
        uint16_t old = *ttlptr;
        --(ipv4->time_to_live);
        ipv4->hdr_checksum 
            = checksum_incremental_16(
            ipv4->hdr_checksum, old, *ttlptr);
}

void printchecksum (struct ipv4_header *ip, char *prefix)
{
  uint16_t verify = ipv4_cksum(&(ip->dpdk)); 
  uint16_t oldsum = ip->hdr_checksum;
  ip->hdr_checksum = 0;
  uint16_t resum = ipv4_cksum(&(ip->dpdk));
  ip->hdr_checksum = oldsum;
  printf ("%s -> incremental(%x) =? resum(%x), verify: %x\n", prefix, ip->hdr_checksum,
      resum, verify);
}

int main (void) {
    char *hex = "441e a144 703f 70db 9839 19bf 0800 4500"
                "005b 2fbd 4000 3806 39fe c721 e1c4 c6f4"
                "6907 0016 c20e 89aa 529c ab62 1357 8018"
                "00d9 b6f5 0000 0101 080a 1bd0 7d22 0ecc"
                "4a61 5353 482d 322e 302d 4f70 656e 5353"
                "485f 372e 3470 3120 4465 6269 616e 2d31"
                "302b 6465 6239 7534 0a";

    uint8_t packet[1500];
    uint16_t len = hex_to_binary(hex,packet,1500);

    printf ("len=%d\n",len);
    struct ethernet_header *eth = (struct ethernet_header*) packet;
    struct ipv4_header *ip = (struct ipv4_header*) &(eth[1]);
    printf ("Source: " PRI_IPV4 "\n", PRI_IPV4_V(ip->src));
    uint16_t sum = ipv4_cksum(&(ip->dpdk)); 
    printf ("IPv4 checksum = %x, verify: %x\n", ip->hdr_checksum, sum);

    decrement_ttl(ip);
    printchecksum (ip,"IPv4 checksum after decrement ");

    struct tcp_hdr *tcp = (struct tcp_hdr*) &(ip[1]);

    /* change IP to force an overflow on checksum */
    struct ipv4_address ip4;
    sscanf("199.33.30.195", SCN_IPV4, SCN_IPV4_V(ip4));
    ip->hdr_checksum = checksum_incremental_32(ip->hdr_checksum,
        ip->src.whole, ip4.whole);
    tcp->cksum = checksum_incremental_32(
        tcp->cksum, ip->src.whole, ip4.whole);
    ip->src.whole = ip4.whole;
    sum = ipv4_cksum(&(ip->dpdk));
    printf ("IPv4 checksum after " PRI_IPV4 " = %x, verify: %x\n",
        PRI_IPV4_V(ip4), ip->hdr_checksum, sum);
 
    decrement_ttl(ip);
    printchecksum (ip,"IPv4 checksum after decrement ");

    decrement_ttl(ip);
    printchecksum (ip,"IPv4 checksum after decrement ");
    ip->hdr_checksum = 0xffff;
    printchecksum (ip,"IPv4 checksum tweaked ");

    decrement_ttl(ip);
    printchecksum (ip,"IPv4 checksum after decrement ");

    /* change IP to force an overflow on checksum */
    sscanf("199.33.31.195", SCN_IPV4, SCN_IPV4_V(ip4));
    ip->hdr_checksum = checksum_incremental_32(ip->hdr_checksum,
        ip->src.whole, ip4.whole);
    tcp->cksum = checksum_incremental_32(
        tcp->cksum, ip->src.whole, ip4.whole);
    ip->src.whole = ip4.whole;
    sum = ipv4_cksum(&(ip->dpdk));
    printf ("IPv4 checksum after " PRI_IPV4 " = %x, verify: %x\n",
        PRI_IPV4_V(ip4), ip->hdr_checksum, sum);
 
    uint16_t tsum = ipv4_tcp_cksum(&(ip->dpdk), tcp);
    printf ("TCP checksum = %x\n", tsum);

    uint64_t i;
    uint32_t orig_src = ip->src.whole;
    uint16_t orig_csum = tcp->cksum;
    uint32_t i_be;
    uint16_t orig_port = tcp->dst_port;
    uint16_t port_be;
    for (i=0; i<0x10000LLU; i++) {
        tcp->cksum = orig_csum;
        tcp->dst_port = orig_port;
        port_be = rte_cpu_to_be_16((uint16_t) i);
        tcp->cksum = checksum_incremental_16(
            tcp->cksum, tcp->dst_port, port_be);
        tcp->dst_port = port_be;
        tsum = ipv4_tcp_cksum(&(ip->dpdk), tcp);
        printf ("Checksum: old=%04x new=%04x -> %04x " PRI_IPV4 ":%d   \r",
            orig_csum, tcp->cksum, tsum, PRI_IPV4_V(ip->src), (int) i);
        if (tsum || (tcp->cksum==0xFFFF)) printf ("\n");
    }
    printf ("\n");
    tcp->dst_port = orig_port;
    for (i=0; i<0x100000000LLU; i++) {
        tcp->cksum = orig_csum;
        ip->src.whole = orig_src;
        i_be = rte_cpu_to_be_32((uint32_t) i);
        tcp->cksum = checksum_incremental_32(tcp->cksum, ip->src.whole, i_be);
        ip->src.whole = i_be;
        tsum = ipv4_tcp_cksum(&(ip->dpdk), tcp);
        if ((0==(i & 0xFFFFFU)) || tsum || (tcp->cksum==0xFFFF)) {
            printf ("Checksum: old=%04x new=%04x -> %04x " PRI_IPV4 "   \r",
                orig_csum, tcp->cksum, tsum, PRI_IPV4_V(ip->src));
            fflush(stdout);
            if (tsum || (tcp->cksum==0xFFFF)) printf ("\n");
        }
    }
    printf ("\n");

    return 0;
}
