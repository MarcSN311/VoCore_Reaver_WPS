#ifndef KEYEXCHANGE_H
#define KEYEXCHANGE_H

#include "../crypto/aes_wrap.h"
#include "../crypto/crypto.h"
#include "../crypto/dh_group5.h"
#include "../crypto/sha256.h"
#include "../crypto/wpabuf.h"
#include "../helpers.h"
#include "../send.h"
#include <byteswap.h>
#include <stdio.h>

int wps_build_key(WPSDATA *data, uint8_t *wpspin);
void send_m2(pcap_t *handle, WPSDATA *data, MAC addr1, MAC addr2, MAC addr3);
void send_m4(pcap_t *handle, WPSDATA *data, MAC addr1, MAC addr2, MAC addr3);
void send_m6(pcap_t *handle, WPSDATA *data, MAC addr1, MAC addr2, MAC addr3);
void send_wsc_nack(pcap_t *handle, uint8_t wsc_id, WPSDATA *data, MAC addr1,
                   MAC addr2, MAC addr3);

#endif
