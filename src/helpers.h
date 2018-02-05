#ifndef HELPERS_H
#define HELPERS_H

#include "WPS/headers.h"
#include <linux/if.h>
#include <malloc.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

typedef struct {
  uint8_t n1[16];
  uint8_t n2[16];
  uint8_t pke[192];
  uint8_t pkr[192];
  uint8_t psk1[16];
  uint8_t psk2[16];
  uint8_t rhash1[32];
  uint8_t rhash2[32];
  uint8_t ehash1[32];
  uint8_t ehash2[32];
  uint8_t plain_rs1[16];
  uint8_t plain_rs2[16];
  uint8_t iv[16];
  uint8_t rs1[64];
  uint8_t rs2[64];
  uint8_t es1[64];
  uint8_t es2[64];

  uint8_t authkey[32];
  uint8_t keywrapkey[16];
  uint8_t emsk[32];

  uint8_t *enc_key;
  uint8_t enc_key_len;

  MAC mac;

  uint8_t *last_msg;
  size_t last_msg_len;

  void *dh_ctx;
} WPSDATA;

typedef struct {
  MAC targetmac;
  uint8_t *rates;
  size_t rates_len;
  WPSDATA wps;
} returninfo;

typedef struct {
  pcap_t *handle;
  char *targetssid;
  returninfo *ret;
} loopinfo;

void printip(bpf_u_int32 ip);
void printMAC(MAC *m);
void printpacket(const unsigned char *p, int len);
int get_random(unsigned char *buf, size_t len);
MAC *getMAC();
void *zalloc(size_t size);

#endif
