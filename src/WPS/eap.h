#ifndef EAP_H
#define EAP_H

#include "../send.h"
#include "headers.h"
#include <linux/byteorder/little_endian.h>
#include <stdio.h>

void eapol_start(pcap_t *handle, MAC addr1, MAC addr2, MAC addr3);
void eap_identity_response(pcap_t *handle, MAC addr1, MAC addr2, MAC addr3);

#endif
