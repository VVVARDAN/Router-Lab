#include "lookup.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <bitset>


std::vector<RoutingTableEntry> table;

in6_addr Netaddr(RoutingTableEntry now)
{
	return len_to_mask(now.len) & now.addr;
}


void update(bool insert, const RoutingTableEntry entry) {
  // TODO
  //uint32_t addr = entry.addr, mask = (1ULL << entry.len) - 1;
  //mask = entry.len;
  auto pos = table.end();
  if(insert){
    for(int i = 0;i<table.size();i++){
      if((table[i].addr&len_to_mask(entry.len)) == (entry.addr&len_to_mask(entry.len)) && table[i].len == entry.len){
        table[i] = entry;
				return;
      }
    }
    table.push_back(entry);
    return;
  }
  for (int i = 0; i < table.size(); i++)
			if (table[i].len == entry.len && (table[i].addr&len_to_mask(entry.len)) == (entry.addr&len_to_mask(entry.len)))
			{
				table.erase(table.begin() + i);
				return;
			}
}

bool prefix_query(const in6_addr addr, in6_addr *nexthop, uint32_t *if_index) {
  // TODO
  uint32_t max = 0;
  bool found = false;
  uint32_t  if_index1;
  in6_addr nexthop1;
  for (const auto &e : table) {
    if (e.len>=max && (addr & len_to_mask(e.len)) == e.addr) {
      max = e.len;
      found = true;
      nexthop1 = e.nexthop;
      if_index1 = e.if_index;
    }
  }
  if (found) {
    *nexthop = nexthop1;
    *if_index = if_index1;
    return true;
  }
  return false;
}

int mask_to_len(const in6_addr mask) {
  int len = 0;
  /*printf("check mask to len\n");
  for(int i = 0;i<16;i++){
    printf("%lx ",mask.s6_addr[i]);
  }
  printf("\n");*/
  for(int i = 0;i<16;i++){ 
      /*if(mask.s6_addr[i] == 0xff){ 
        len+=8;
        continue;
      }*/
      int prev = len;
      std::bitset<8> set(mask.s6_addr[i]);
      for(int j = 7;j>=0;j--){
        //printf("%d ",set.test(j));
        if(set.test(j)) len++;
        else break;
      }
      //printf("\n");
      if((len-prev)!=8) break;
  }
  //printf("ALLLLERRRTTT %d\n",len);
  /*for(int i = 0;i<16;i++){
    printf("%lx ",mask.s6_addr[i]);
  }
  printf("\n");*/
  //printf("ALLLLERRRRRRRT ");
  //printf("%d\n",len);
  return len;
  // TODO
  return -1;
}

in6_addr len_to_mask(int len) {
  if(len<0 || len>128) return {};
  //printf("%d\n",len);
  in6_addr new_mask;
  for(int i = 0;i<16;i++) new_mask.s6_addr[i] = 0x00;
  int cur = 0;
  while(len){
    if(len>=16){
        new_mask.s6_addr[cur] = new_mask.s6_addr[cur+1] = 0xff;
        len-=16;
        cur+=2;
        continue;
    }
    else if(len>=8){
        new_mask.s6_addr[cur] = 0xff;
        len-=8;
        cur++;
        continue;
    }
    else if (len == 7) new_mask.s6_addr[cur] = 0xfe;
    else if (len == 6) new_mask.s6_addr[cur] = 0xfc;
    else if (len == 5) new_mask.s6_addr[cur] = 0xf8;
    else if (len == 4) new_mask.s6_addr[cur] = 0xf0;
    else if (len == 3) new_mask.s6_addr[cur] = 0xe0;
    else if (len == 2) new_mask.s6_addr[cur] = 0xc0;
    else if (len == 1) new_mask.s6_addr[cur] = 0x80;
    else if (len == 0) new_mask.s6_addr[cur] = 0x00;
    break;
  }
  return new_mask;
  /*for(int i = 0;i<16;i++){
    printf("%lx ",new_mask.s6_addr[i]);
  }
  printf("\n");*/
  // TODO
  return {};
}

