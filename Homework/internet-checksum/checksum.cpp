#include "checksum.h"
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>

using namespace std;

uint16_t udp_checksum(uint8_t *packet, size_t len){
      len-=4;
      uint32_t i = 4;
      uint32_t checksum = 0;

      while(len >= 2)
      {
        if(i == 6){
          checksum += packet[i];
          i+=2;
          len-=2;
          continue;
        }
        checksum += ((packet[i] << 8) & 0xff00) | packet[i + 1];
        if (checksum & 0x80000000)
            checksum = (checksum & 0xFFFF) + (checksum >> 16);
        i += 2;
        len -= 2;
      }

      if(len)
      {
        checksum += (packet[i] << 8) & 0xff00;
      }
      while(checksum >> 16)
      {
        checksum = (checksum >> 16) + (checksum & 0xffff);
      }
      return (uint16_t)(~checksum);
}

bool validateAndFillChecksum(uint8_t *packet, size_t len) {
  // TODO
  struct ip6_hdr *ip6 = (struct ip6_hdr *)packet;

  // check next header
  uint8_t nxt_header = ip6->ip6_nxt;
  if (nxt_header == IPPROTO_UDP) {
    // UDP
    struct udphdr *udp = (struct udphdr *)&packet[sizeof(struct ip6_hdr)];
    uint16_t prev_checksum = ((packet[46] << 8) & 0xff00) | packet[47];
    packet[46] = packet[47] = 0;
    uint16_t cur_checksum = udp_checksum(packet,len);
    //cout<<prev_checksum<<" "<<cur_checksum<<endl;
    if(cur_checksum == 0 && prev_checksum == 0xFFFF) cur_checksum = 0xFFFF;
    if(cur_checksum == 0 && prev_checksum == 0) {
      cur_checksum = 0xFFFF;
      packet[46] = cur_checksum >> 8;
      packet[47] = cur_checksum & 0xff;
      return false;
    }
    //cout<<"cur checksum: "<<cur_checksum<<endl;
    packet[46] = cur_checksum >> 8;
    packet[47] = cur_checksum & 0xff;
    if(prev_checksum == cur_checksum) return true;
    else return false;
    // length: udp->uh_ulen
    // checksum: udp->uh_sum
  } else if (nxt_header == IPPROTO_ICMPV6) {
    // ICMPv6
    struct icmp6_hdr *icmp =
        (struct icmp6_hdr *)&packet[sizeof(struct ip6_hdr)];

        uint16_t prev_checksum = ((packet[42] << 8) & 0xff00) | packet[43];
        packet[42] = packet[43] = 0;
        uint16_t cur_checksum = udp_checksum(packet,len);
        //cout<<prev_checksum<<" "<<cur_checksum<<endl;
        if(cur_checksum == 0 && prev_checksum == 0xFFFF) return true;
        //cout<<"cur checksum: "<<cur_checksum<<endl;
        packet[42] = cur_checksum >> 8;
        packet[43] = cur_checksum & 0xff;
        if(prev_checksum == cur_checksum) return true;
        else return false;
  //  cout<<"icmp6 length: "<<len-sizeof(struct ip6_hdr)<<endl;
    // length: len-sizeof(struct ip6_hdr)
    // checksum: icmp->icmp6_cksum
  } else {
    assert(false);
  }
  return true;
}
