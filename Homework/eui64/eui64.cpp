#include "eui64.h"
#include <stdint.h>
#include <stdlib.h>
#include <iostream>
#include <bitset>

using namespace std;

in6_addr eui64(const ether_addr mac) {
  in6_addr res = {0};
  res.s6_addr[0] = 0xFE;
  res.s6_addr[1] = 0x80;
  for(int i = 0;i<3;i++){
    res.s6_addr[i+8] = mac.ether_addr_octet[i];
  }
  for(int i = 3;i<6;i++){
    res.s6_addr[i+10] = mac.ether_addr_octet[i];
  }
  res.s6_addr[11] = 0xFF;
  res.s6_addr[12] = 0xFE;
  bitset<8> set(res.s6_addr[8]);
  set[1] = (!set[1]);
  res.s6_addr[8] = set.to_ulong();
  return res;
}