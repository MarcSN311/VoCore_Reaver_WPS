#ifndef SEND_H
#define SEND_H

#include "WPS/headers.h"
#include <pcap.h>

int send_packet(pcap_t *handle, const void *packet, const size_t len);
int get_radiotap_header_len(pcap_t *handle, const void *frame);
void *get_packet(pcap_t *handle, struct pcap_pkthdr *header);

#endif
