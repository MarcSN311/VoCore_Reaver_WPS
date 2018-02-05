#include "authenticate.h"

void deauthenticate(pcap_t *handle, MAC addr1, MAC addr2, MAC addr3) {
  size_t packet_len = 0;

  const radiotap_header *radio_tap = NULL;
  const ieee802dot11_header *dot11_frame = NULL;
  const void *packet = NULL;

  radio_tap = build_radiotap_header();
  dot11_frame =
      build_ieee802dot11_header(FC_DEAUTHENTICATE, addr1, addr2, addr3);

  packet_len =
      sizeof(*radio_tap) + sizeof(*dot11_frame) + DEAUTH_REASON_CODE_SIZE;

  if (radio_tap && dot11_frame) {
    if ((packet = malloc(packet_len))) {
      memset((void *)packet, 0, packet_len);

      memcpy((void *)packet, radio_tap, sizeof(*radio_tap));
      memcpy((void *)((char *)packet + sizeof(*radio_tap)), dot11_frame,
             sizeof(*dot11_frame));
      memcpy(
          (void *)((char *)packet + sizeof(*radio_tap) + sizeof(*dot11_frame)),
          DEAUTH_REASON_CODE, DEAUTH_REASON_CODE_SIZE);

      send_packet(handle, packet, packet_len);

      free((void *)packet);
    }
  }

  if (radio_tap)
    free((void *)radio_tap);
  if (dot11_frame)
    free((void *)dot11_frame);

  return;
}

authentication_management_frame *build_authentication_management_frame() {
  authentication_management_frame *frame = NULL;

  if ((frame = (authentication_management_frame *)malloc(
           sizeof(authentication_management_frame)))) {
    memset((void *)frame, 0, sizeof(frame));

    frame->algorithm = OPEN_SYSTEM;
    frame->sequence = 1;
    frame->status = 0;
  }

  return frame;
}

void authenticate(pcap_t *handle, MAC addr1, MAC addr2, MAC addr3) {
  const radiotap_header *radio_tap = NULL;
  const ieee802dot11_header *dot11_frame = NULL;
  const authentication_management_frame *management_frame = NULL;
  const void *packet = NULL;
  size_t packet_len;

  radio_tap = build_radiotap_header();
  dot11_frame = build_ieee802dot11_header(FC_AUTHENTICATE, addr1, addr2, addr3);
  management_frame = build_authentication_management_frame();
  packet_len =
      sizeof(*radio_tap) + sizeof(*dot11_frame) + sizeof(*management_frame);

  if (radio_tap && dot11_frame && management_frame) {
    if ((packet = malloc(packet_len))) {
      memset((void *)packet, 0, packet_len);

      memcpy((void *)packet, radio_tap, sizeof(*radio_tap));
      memcpy((void *)((char *)packet + sizeof(*radio_tap)), dot11_frame,
             sizeof(*dot11_frame));
      memcpy(
          (void *)((char *)packet + sizeof(*radio_tap) + sizeof(*dot11_frame)),
          management_frame, sizeof(*management_frame));

      send_packet(handle, packet, packet_len);

      free((void *)packet);
    }
  }

  if (radio_tap)
    free((void *)radio_tap);
  if (dot11_frame)
    free((void *)dot11_frame);
  if (management_frame)
    free((void *)management_frame);

  return;
}
