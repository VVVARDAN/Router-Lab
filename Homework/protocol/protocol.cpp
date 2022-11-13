#include "protocol.h"
#include "common.h"
#include "lookup.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>

using namespace std;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define BE16(x) __builtin_bswap16(x)
#define BE32(x) __builtin_bswap32(x)
#else
#define BE16(x) x
#define BE32(x) x
#endif

using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;

struct iphdr {
  u8 ihl : 4, version : 4;
  u8 tos;
  u16 tot_len;
  u16 id;
  u16 frag_off;
  u8 ttl;
  u8 protocol;
  u16 check;
  u32 saddr;
  u32 daddr;
};

struct RawRip {
  u8 command;  // 1(request) or 2(reponse)
  u8 version;  // 2
  u16 zero;
  struct Entry {
    u16 family;  // 0(request) or 2(response)
    u16 tag;     // 0
    u32 addr;
    u32 mask;  // todo
    u32 nexthop;
    u32 metric;  // [1, 16]
  } entries[0];
};


RipngErrorCode disassemble(const uint8_t *packet, uint32_t len,
                         RipngPacket *output) {
  // TODO
  // for(int i = 0;i<len;i++){
  //   cout<<(int)packet[i]<<" ";
  // }
  // cout<<endl;
  uint8_t *cur = new uint8_t[4];
  for(int i = 0;i<4;i++) cur[i]=packet[i+48];
  ripng_hdr *hdr = (ripng_hdr *)cur;
  output->command = hdr->command;
  //cout<<(int)hdr->version<<endl;
  output->numEntries = 0;
  for(int i = 52;i<len;i+=20){
      uint8_t *cur_entry = new uint8_t[20];
      for(int j = 0;j<20;j++) cur_entry[j] = packet[i+j];
      ripng_rte *rte = (ripng_rte *)cur_entry;
      //cout<<"metric: "<<(int)rte->metric<<endl;
      output->entries[output->numEntries++] = *rte;
  }
  //cout<<"my entr: " << output->numEntries<<endl;
  if(len<40) return RipngErrorCode::ERR_LENGTH;
  int k = ((packet[4] << 8) & 0xff00) | packet[5];
  if(k+40!=len) return RipngErrorCode::ERR_LENGTH;
  if(packet[6]!=17) return RipngErrorCode::ERR_IPV6_NEXT_HEADER_NOT_UDP;
  if(k<8) return RipngErrorCode::ERR_LENGTH;
  k = ((packet[40] << 8) & 0xff00) | packet[41];
  int u = ((packet[42] << 8) & 0xff00) | packet[43];
  if(u!=521 || k!=521) return RipngErrorCode::ERR_UDP_PORT_NOT_RIPNG;
  int udp_len = ((packet[44] << 8) & 0xff00) | packet[45];
  //cout<<udp_len<<endl;
  if(!(udp_len%12==0 || udp_len%32 == 0 || udp_len%92 == 0 || udp_len%1432 == 0)) return RipngErrorCode::ERR_LENGTH;
  if(hdr->command!=1 && hdr->command!=2) return RipngErrorCode::ERR_RIPNG_BAD_COMMAND;
  if(hdr->version!=1) return RipngErrorCode::ERR_RIPNG_BAD_VERSION;
  if(hdr->zero!=0) return RipngErrorCode::ERR_RIPNG_BAD_ZERO;
  for(int i = 0;i<output->numEntries;i++){
    if(output->entries[i].metric == 0xFF && !(output->entries[i].prefix_len == 0)){
        return RipngErrorCode::ERR_RIPNG_INCONSISTENT_PREFIX_LENGTH;
    }
    if(output->entries[i].metric == 0xFF && !(output->entries[i].route_tag == 0)){
        return RipngErrorCode::ERR_RIPNG_BAD_ROUTE_TAG;
    }
    if(output->entries[i].metric != 0xFF){
      //TODO
      return RipngErrorCode::ERR_RIPNG_BAD_METRIC;
    }
  }
  //cout<<len<<endl;
  // if(packet[6]!=17) return RipngErrorCode::ERR_IPV6_NEXT_HEADER_NOT_UDP;
  // if(len<40) return RipngErrorCode::ERR_LENGTH;
  // int k = ((packet[4] << 8) & 0xff00) | packet[5];
  // if(k+40!=len) return RipngErrorCode::ERR_LENGTH;
  // k = ((packet[40] << 8) & 0xff00) | packet[41];
  // int u = ((packet[42] << 8) & 0xff00) | packet[43];
  // if(u!=521 || k!=521) return RipngErrorCode::ERR_UDP_PORT_NOT_RIPNG;

  // if((int)packet[48]!=1 && (int)packet[48]!=2) return RipngErrorCode::ERR_RIPNG_BAD_COMMAND;
  // if(packet[49]!=0x01) return RipngErrorCode::ERR_RIPNG_BAD_VERSION;
  // if(packet[50]!=0x00 || packet[51]!=0x00) return RipngErrorCode::ERR_RIPNG_BAD_ZERO;
  //ripng_hdr *hdr = (ripng_hdr *)(packet+49,packet+52);
  //cout<<hdr->command<<endl;
  return RipngErrorCode::SUCCESS;
}

uint32_t assemble(const RipngPacket *rip, uint8_t *buffer) {
  // TODO
 // buffer+=4;
  
  buffer[0] = (int)rip->command;
  //cout<<"cur com: "<<(int)buffer[0]<<endl;
  buffer[1] = 0x01;
  buffer[2] = buffer[3] = 0x00;
  /*for (uint32_t i = 0; i < 4; i++) {
        printf("%02x ", buffer[i]);
  }
  cout<<endl;*/
  buffer+=4;
  int u = 0;
  int i = 0;
  while(u<rip->numEntries){
    //ripng_rte cur = (ripng_rte) rip->entries[u];
    for(int j = 0;j<16;j++){ 
      buffer[i+j] = rip->entries[u].prefix_or_nh.s6_addr[j];
    //cout<<rip->entries[u].prefix_or_nh.s6_addr<<" ";
    }
    //cout<<endl;
    //buffer[i+16] = rip->entries[u].route_tag >> 8;
    //buffer[i+17] = rip->entries[u].route_tag & 0xff;
    //buffer[i+18] = (int)rip->entries[u].prefix_len;
    buffer[i+19] = (int)rip->entries[u].metric;
    //cout<<"metric: "<<(int)rip->entries[u].metric<<endl;
    //printf("%02x ", buffer[i+19]);
    i+=20;
    u++;
  }
  //printf("%02x ", buffer[19]);
  //cout<<endl;
  //cout<<"command here: "<<rip->command<<endl;
  //raw->command = rip->command;
  
  /*raw->numEntries = rip->numEntries;
  for(int i = 0;i<raw->numEntries;i++){
    //cout<<"route tag: " << rip->entries[i].route_tag<<endl;
    //raw->entries[i] = rip->entries[i];
    
     raw->entries[i].prefix_or_nh = rip->entries[i].prefix_or_nh;
     raw->entries[i].route_tag = rip->entries[i].route_tag;
     raw->entries[i].prefix_len = rip->entries[i].prefix_len;
     raw->entries[i].metric = rip->entries[i].metric;
  }*/
  //cout<<"entry num: " << rip->numEntries<<endl;
  //cout<<"command "<<raw->command<<endl;
  /*u32 count = rip->numEntries;
  raw->command = rip->command;
  raw->version = 2;
  raw->zero = 0;
  u16 family = rip->command == 1 ? 0 : BE16(2);
  for (u32 i = 0; i < count; ++i) {
    ripng_rte::Entry *dst = &raw->entries[i];
    //dst->family = family;
    dst->route_tag = 0;
    memcpy(&dst->addr, &rip->entries[i], 4 * sizeof(u32));
  }*/
  return 4 + 20 * rip->numEntries;
}