#include "test_helpers.h"
#include "addresses.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <rte_icmp.h>

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

/*
 * 00:00:00.000000 IP (tos 0x0, ttl 254, id 0, offset 0, flags [none], proto ICMP (1), length 56)
 *     52.93.70.195 > 99.82.158.4: ICMP 198.244.105.7 unreachable - need to frag (mtu 1500), length 36
 *         IP (tos 0x0, ttl 251, id 43497, offset 0, flags [DF], proto TCP (6), length 1600)
 *     99.82.158.4.80 > 198.244.105.7.34020:  tcp 1580 [bad hdr length 0 - too short, < 20]
 *         0x0000:  01f3 0800 4500 0038 0000 0000 fe01 404e  ....E..8......@N
 *         0x0010:  345d 46c3 6352 9e04 0304 32a7 0000 05dc  4]F.cR....2..... << icmp checksum, mtu
 *         0x0020:  4500 0640 a9e9 4000 fb06 9e7b 6352 9e04  E..@..@....{cR.. << reflected IPv4 checksum, source IP
 *         0x0030:  c6f4 6907 0050 84e4 15cc 2978            ..i..P....)x
 * 00:00:00.000000 IP (tos 0x0, ttl 128, id 0, offset 0, flags [DF], proto UDP (17), length 146)
 *     69.107.0.192.47252 > 54.239.0.32.60459: UDP, length 118
 *         0x0000:  01f3 0800 4500 0092 0000 4000 8011 7d21  ....E.....@...}!
 *         0x0010:  456b 00c0 36ef 0020 b894 ec2b 007e 4b6f  Ek..6......+.~Ko
 *         0x0020:  4000 2fe8 0436 43d6 0436 43d5 4500 006a  @./..6C..6C.E..j
 *         0x0030:  0000 4000 8011 1db8 0a00 1002 c0a8 0221  ..@............!
 *         0x0040:  b894 17c1 0056 0000 0000 6558 93ea bc00  .....V....eX....
 *         0x0050:  0011 2233 4455 0099 ac10 00c3 0800 4500  .."3DU........E.
 *         0x0060:  0038 0000 0000 fc01 96d1 345d 46c3 ac10  .8........4]F...
 *         0x0070:  00c3 0304 223a 0000 05dc 4500 0640 a9e9  ....":....E..@..
 *         0x0080:  4000 fb06 f2fe ac10 00c3 c6f4 6907 0050  @...........i..P
 *         0x0090:  84e4 15cc 2978                           ....)x
 * 
 * 22:44:06.588591 IP (tos 0x0, ttl 251, id 0, offset 0, flags [none], proto ICMP (1), length 56)
 *     52.93.70.195 > 172.16.0.195: ICMP 198.244.105.7 unreachable - need to frag (mtu 1500), length 36 (wrong icmp cksum 223a (->32a7)!)
 *         IP (tos 0x0, ttl 251, id 43497, offset 0, flags [DF], proto TCP (6), length 1600)
 *     172.16.0.195.80 > 198.244.105.7.34020:  tcp 1580 [bad hdr length 0 - too short, < 20]
 *         0x0000:  4500 0038 0000 0000 fb01 97d1 345d 46c3  E..8........4]F.
 *         0x0010:  ac10 00c3 0304 223a 0000 05dc 4500 0640  ......":....E..@
 *         0x0020:  a9e9 4000 fb06 f2fe ac10 00c3 c6f4 6907  ..@...........i.
 *         0x0030:  0050 84e4 15cc 2978                      .P....)x
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

static inline uint32_t
__raw_cksum(const void *buf, size_t len, uint32_t sum)
{
        /* workaround gcc strict-aliasing warning */
        uintptr_t ptr = (uintptr_t)buf;
        typedef uint16_t __attribute__((__may_alias__)) u16_p;
        const u16_p *u16_buf = (const u16_p *)ptr;

        while (len >= (sizeof(*u16_buf) * 4)) {
                sum += u16_buf[0];
                sum += u16_buf[1];
                sum += u16_buf[2];
                sum += u16_buf[3];
                len -= sizeof(*u16_buf) * 4;
                u16_buf += 4;
        }
        while (len >= sizeof(*u16_buf)) {
                sum += *u16_buf;
                len -= sizeof(*u16_buf);
                u16_buf += 1;
        }

        /* if length is in odd bytes */
        if (len == 1)
                sum += *((const uint8_t *)u16_buf);

        return sum;
}

static inline uint16_t
__raw_cksum_reduce(uint32_t sum)
{
        sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
        sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
        return (uint16_t)sum;
}

static inline uint16_t
raw_cksum(const void *buf, size_t len)
{
        uint32_t sum;

        sum = __raw_cksum(buf, len, 0);
        sum = __raw_cksum_reduce(sum);
        return (uint16_t)~sum;
}

int main (void) {
    /* original icmp pmtud packet */
    char *ohex = "4500 0038 0000 0000 fe01 404e"
		"345d 46c3 6352 9e04 0304 32a7 0000 05dc"
		"4500 0640 a9e9 4000 fb06 9e7b 6352 9e04"
		"c6f4 6907 0050 84e4 15cc 2978";
    char *hex = "4500 0038 0000 0000 fb01 97d1 345d 46c3"
		"ac10 00c3 0304 223a 0000 05dc 4500 0640"
		"a9e9 4000 fb06 f2fe ac10 00c3 c6f4 6907"
		"0050 84e4 15cc 2978";

    uint8_t packet[1500];
    uint16_t len = hex_to_binary(hex,packet,1500);

    printf ("len=%d\n",len);
    struct ipv4_header *ip = (struct ipv4_header*) packet;
    printf ("Source: " PRI_IPV4 "\n", PRI_IPV4_V(ip->src));
    uint16_t sum = ipv4_cksum(&(ip->dpdk)); 
    printf ("IPv4 checksum = %x, verify: %x\n", (uint32_t) ip->hdr_checksum, (uint32_t) sum);
    sum = raw_cksum (ip, 20);
    printf ("IPv4 checksum = %x, raw: %x\n", (uint32_t) ip->hdr_checksum, (uint32_t) sum);

    struct icmp_destination_unreachable *icmp = (struct icmp_destination_unreachable*) &(ip[1]);
    printf ("ICMP Type: %d, Code: %d\n", (int)icmp->type, (int)icmp->code);

    struct ipv4_header *inner = (struct ipv4_header*)  &(icmp->original_packet);
    printf ("Inner Source: " PRI_IPV4 "\n", PRI_IPV4_V(inner->src));
    sum = ipv4_cksum(&(inner->dpdk)); 
    printf ("Inner IPv4 checksum = %x, verify: %x\n", inner->hdr_checksum, sum);
    sum = raw_cksum (inner, 20);
    printf ("Inner IPv4 checksum = %x, raw: %x\n", (uint32_t) inner->hdr_checksum, (uint32_t) sum);
    inner->hdr_checksum = 0;
    sum = raw_cksum (inner, 20);
    printf ("Inner IPv4 checksum recompute = %x, raw: %x\n", (uint32_t) inner->hdr_checksum, (uint32_t) sum);
    inner->hdr_checksum = sum;

    uint16_t inner_len = len - ((uint16_t)((void*)icmp - (void*)packet));
    printf ("Inner len=%d\n",inner_len);
    sum = raw_cksum ((void*) icmp, (size_t) inner_len);
    printf ("ICMP checksum = %x, raw: %x\n", (uint32_t) icmp->checksum, (uint32_t) sum);
    icmp->checksum = 0; 
    sum = raw_cksum ((void*) icmp, (size_t) inner_len);
    printf ("ICMP checksum recompute = %x, raw: %x\n", (uint32_t) icmp->checksum, (uint32_t) sum);
    icmp->checksum = 0xa732; 
    sum = raw_cksum ((void*) icmp, (size_t) inner_len);
    printf ("ICMP checksum funked up = %x, raw: %x\n", (uint32_t) icmp->checksum, (uint32_t) sum);

    printf ("\n");

    return 0;
}
