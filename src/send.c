#include "send.h"

int send_packet(pcap_t *handle, const void *packet, const size_t len) {
  int ret = pcap_inject(handle, packet, len);
  if (ret == -1)
    pcap_perror(handle, "[libpcap]");
  return ret;
}

int get_radiotap_header_len(pcap_t *handle, const void *frame) {
  if (pcap_datalink(handle) == DLT_IEEE802_11_RADIO) {
    return ((radiotap_header *)frame)->length;
  }
  return 0;
}

void *get_packet(pcap_t *handle, struct pcap_pkthdr *header) {
  const uint8_t *packet = NULL;
  struct pcap_pkthdr *pkt_header;
  int status;

  /* Loop until we get a valid packet, or until we run out of packets */
  while ((status = pcap_next_ex(handle, &pkt_header, &packet)) == 1 ||
         !status) {
    if (!status)
      continue; /* timeout */

    memcpy(header, pkt_header, sizeof(*header));

    break;
  }

  return (void *)packet;
}
