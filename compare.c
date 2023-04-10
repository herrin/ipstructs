#include "addresses.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <rte_byteorder.h>

int main(void) {
  struct ipv6_address ip, two, *three;

  ip.network = 0xFEDCBA9876543210ULL;
  ip.host =    0x0123456789ABCDEFULL;

  printf (PRI_IPV6 "\n", PRI_IPV6_V(ip));
  three = &ip;
  two = *three;
  if (two.whole == three->whole) {
      printf("Yes!\n");
  }

  struct ipv4_address ip4, five, *six, mask, net;
  sscanf("192.168.1.1", SCN_IPV4, SCN_IPV4_V(ip4));
  printf (PRI_IPV4 " = 0x%08x\n", PRI_IPV4_V(ip4), ip4.whole);

  six = &ip4;
  five = *six;
  if (five.whole == six->whole) {
      printf("Yes!\n");
  }

  mask.whole = 0;
  sscanf("255.255.0.0", SCN_IPV4, SCN_IPV4_V(mask));
  printf ("Mask = 0x%08x\n",mask.whole);
  sscanf("192.168.0.0", SCN_IPV4, SCN_IPV4_V(net));
  if ((ip4.whole & mask.whole) == net.whole) {
      printf ("Same net!\n");
  }

  printf ("%s: Sizeof(ethernet_address)=%lu, expecting %d\n",
     (sizeof(struct ethernet_address)==ETHER_ADDR_LEN)?"OK":"FAIL",
     sizeof(struct ethernet_address),ETHER_ADDR_LEN);
  printf ("%s: Sizeof(ethernet_header)=%lu, expecting %d\n",
     (sizeof(struct ethernet_header)==ETHER_HDR_LEN)?"OK":"FAIL",
     sizeof(struct ethernet_header),ETHER_HDR_LEN);
  printf ("%s: Sizeof(ethernet_header_1vlan)=%lu, expecting %d\n",
     (sizeof(struct ethernet_header_1vlan)==ETHER_HDR_LEN+4)?"OK":"FAIL",
     sizeof(struct ethernet_header_1vlan),ETHER_HDR_LEN+4);

  printf ("%s: Sizeof(ipv4_address)=%lu, expecting %d\n",
     (sizeof(struct ipv4_address)==4)?"OK":"FAIL",
     sizeof(struct ipv4_address),4);
  printf ("%s: Sizeof(ipv4_header)=%lu, expecting %lu\n",
     (sizeof(struct ipv4_header)==sizeof(struct ipv4_hdr))?"OK":"FAIL",
     sizeof(struct ipv4_header),sizeof(struct ipv4_hdr));
  struct ipv4_header iph = { 0 };
  iph.dont_fragment = 1;
  printf ("%s: fragment=%x expecting %x\n",
      (rte_be_to_cpu_16(iph.dpdk.fragment_offset)&IPV4_HDR_DF_FLAG)==0
      ?"FAIL":"OK",
      rte_be_to_cpu_16(iph.dpdk.fragment_offset),IPV4_HDR_DF_FLAG);
  sscanf("192.168.1.1", SCN_IPV4, SCN_IPV4_V(iph.src));
  printf ("%s: address %x expecting %x (" PRI_IPV4 ")\n",
      (rte_be_to_cpu_32(iph.dpdk.src_addr)==0xC0A80101U)?"OK":"FAIL",
      rte_be_to_cpu_32(iph.dpdk.src_addr),0xC0A80101U,
      PRI_IPV4_V(iph.src));
  
  printf ("%s: Sizeof(ipv6_address)=%lu, expecting %d\n",
     (sizeof(struct ipv6_address)==16)?"OK":"FAIL",
     sizeof(struct ipv6_address),16);
  printf ("%s: Sizeof(ipv6_header)=%lu, expecting %lu\n",
     (sizeof(struct ipv6_header)==sizeof(struct ipv6_hdr))?"OK":"FAIL",
     sizeof(struct ipv6_header),sizeof(struct ipv6_hdr));
  return 0;
}
