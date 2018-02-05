#include "associate.h"

association_request_management_frame *build_association_management_frame() {
  association_request_management_frame *frame = NULL;

  if ((frame = (association_request_management_frame *)malloc(
           sizeof(association_request_management_frame)))) {
    memset((void *)frame, 0, sizeof(frame));

    frame->capability = 0;
    frame->listen_interval = LISTEN_INTERVAL;
  }

  return frame;
}

void associate(pcap_t *handle, char *ssid, uint8_t *srates,
               size_t srates_tag_size, MAC addr1, MAC addr2, MAC addr3) {
  radiotap_header *radio_tap = NULL;
  ieee802dot11_header *dot11_frame = NULL;
  association_request_management_frame *management_frame = NULL;
  tagged_parameter *ssid_tag = NULL, *wps_tag = NULL, *rates_tag = NULL;
  unsigned char *packet = NULL;
  size_t packet_len = 0, offset = 0;

  radio_tap = build_radiotap_header();
  dot11_frame = build_ieee802dot11_header(FC_ASSOCIATE, addr1, addr2, addr3);
  management_frame = build_association_management_frame();
  ssid_tag = build_ssid_tagged_parameter(ssid);
  wps_tag = build_wps_tagged_parameter();
  rates_tag = build_supported_rates_tagged_parameter(srates, srates_tag_size);

  packet_len = sizeof(*radio_tap) + sizeof(*dot11_frame) +
               sizeof(*management_frame) + (sizeof(*ssid_tag) + ssid_tag->len) +
               (sizeof(*wps_tag) + wps_tag->len) +
               (sizeof(*rates_tag) + rates_tag->len);

  if (radio_tap && dot11_frame && management_frame && ssid_tag && wps_tag &&
      rates_tag) {
    packet = malloc(packet_len);
    if (packet) {
      memset(packet, 0, packet_len);
      memcpy(packet, radio_tap, sizeof(*radio_tap));
      offset += sizeof(*radio_tap);
      memcpy(packet + offset, dot11_frame, sizeof(*dot11_frame));
      offset += sizeof(*dot11_frame);
      memcpy(packet + offset, management_frame, sizeof(*management_frame));
      offset += sizeof(*management_frame);
      memcpy(packet + offset, ssid_tag, (sizeof(*ssid_tag) + ssid_tag->len));
      offset += (sizeof(*ssid_tag) + ssid_tag->len);
      memcpy(packet + offset, rates_tag, (sizeof(*rates_tag) + rates_tag->len));
      offset += (sizeof(*rates_tag) + rates_tag->len);
      memcpy(packet + offset, wps_tag, (sizeof(*wps_tag) + wps_tag->len));
      send_packet(handle, packet, packet_len);
      free(packet);
    }
  }

  if (radio_tap)
    free(radio_tap);
  if (dot11_frame)
    free(dot11_frame);
  if (management_frame)
    free(management_frame);
  if (ssid_tag)
    free(ssid_tag);
  if (wps_tag)
    free(wps_tag);
  if (rates_tag)
    free(rates_tag);

  return;
}
