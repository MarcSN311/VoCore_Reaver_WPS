#include "eap.h"

void eapol_start(pcap_t *handle, MAC addr1, MAC addr2, MAC addr3) {
  radiotap_header *radio_tap = NULL;
  ieee802dot11_header *dot11_frame = NULL;
  llc_header *llc = NULL;
  ieee802dot1x_header *dot1x = NULL;
  unsigned char *packet = NULL;
  size_t packet_len = 0, offset = 0;

  radio_tap = build_radiotap_header();
  dot11_frame = build_ieee802dot11_header(FC_STANDARD, addr1, addr2, addr3);
  llc = build_llc_header();
  dot1x = build_ieee802dot1x_header(DOT1X_START, 0);

  packet_len =
      sizeof(*radio_tap) + sizeof(*dot11_frame) + sizeof(*llc) + sizeof(*dot1x);

  if (radio_tap && dot11_frame && llc && dot1x) {
    packet = malloc(packet_len);
    if (packet) {
      memset(packet, 0, packet_len);
      memcpy(packet, radio_tap, sizeof(*radio_tap));
      offset += sizeof(*radio_tap);
      memcpy(packet + offset, dot11_frame, sizeof(*dot11_frame));
      offset += sizeof(*dot11_frame);
      memcpy(packet + offset, llc, sizeof(*llc));
      offset += sizeof(*llc);
      memcpy(packet + offset, dot1x, sizeof(*dot1x));
      send_packet(handle, packet, packet_len);
      free(packet);
    }
  }

  if (radio_tap)
    free(radio_tap);
  if (dot11_frame)
    free(dot11_frame);
  if (llc)
    free(llc);
  if (dot1x)
    free(dot1x);

  return;
}

void eap_identity_response(pcap_t *handle, MAC addr1, MAC addr2, MAC addr3) {
  radiotap_header *radio_tap = NULL;
  ieee802dot11_header *dot11_frame = NULL;
  llc_header *llc = NULL;
  ieee802dot1x_header *dot1x = NULL;
  eap_header *eap = NULL;
  unsigned char *packet = NULL;
  size_t packet_len = 0, offset = 0, eap_len = 0;

  radio_tap = build_radiotap_header();
  dot11_frame = build_ieee802dot11_header(FC_STANDARD, addr1, addr2, addr3);
  llc = build_llc_header();
  eap = build_eap_header(0, EAP_RESPONSE, EAP_IDENTITY, strlen(WFA_REGISTRAR));
  dot1x = build_ieee802dot1x_header(DOT1X_EAP_PACKET, eap->length);
  eap_len = ntohs(eap->length);

  packet_len = sizeof(*radio_tap) + sizeof(*dot11_frame) + sizeof(*llc) +
               sizeof(*dot1x) + eap_len;

  if (radio_tap && dot11_frame && llc && dot1x) {
    packet = malloc(packet_len);
    if (packet) {
      memset(packet, 0, packet_len);
      memcpy(packet, radio_tap, sizeof(*radio_tap));
      offset += sizeof(*radio_tap);
      memcpy(packet + offset, dot11_frame, sizeof(*dot11_frame));
      offset += sizeof(*dot11_frame);
      memcpy(packet + offset, llc, sizeof(*llc));
      offset += sizeof(*llc);
      memcpy(packet + offset, dot1x, sizeof(*dot1x));
      offset += sizeof(*dot1x);
      memcpy(packet + offset, eap, sizeof(*eap));
      offset += sizeof(*eap);
      memcpy(packet + offset, WFA_REGISTRAR, eap_len - sizeof(*eap));
      send_packet(handle, packet, packet_len);
      free(packet);
    }
  }

  if (radio_tap)
    free(radio_tap);
  if (dot11_frame)
    free(dot11_frame);
  if (llc)
    free(llc);
  if (dot1x)
    free(dot1x);
  if (eap)
    free(eap);

  return;
}
