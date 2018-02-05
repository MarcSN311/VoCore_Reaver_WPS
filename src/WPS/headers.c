#include "headers.h"

radiotap_header *build_radiotap_header() {
  radiotap_header *rt = NULL;
  if ((rt = (radiotap_header *)malloc(sizeof(radiotap_header)))) {
    memset((void *)rt, 0, sizeof(radiotap_header));
    rt->length =
        sizeof(radiotap_header); // should be okay because CPU is LittleEndian
  }
  return rt;
}

ieee802dot11_header *build_ieee802dot11_header(uint16_t framecontrol, MAC addr1,
                                               MAC addr2, MAC addr3) {
  ieee802dot11_header *header = NULL;
  static uint16_t seqnum;

  if ((header = (ieee802dot11_header *)malloc(sizeof(ieee802dot11_header)))) {
    memset((void *)header, 0, sizeof(ieee802dot11_header));

    seqnum += 0x10;

    header->duration = DEFAULT_DURATION;
    header->framecontrol = framecontrol;
    header->seqnum = seqnum;

    memcpy((void *)&header->addr1, &addr1, sizeof(MAC));
    memcpy((void *)&header->addr2, &addr2, sizeof(MAC));
    memcpy((void *)&header->addr3, &addr3, sizeof(MAC));
  }

  return header;
}

llc_header *build_llc_header() {
  llc_header *header = NULL;
  if ((header = malloc(sizeof(llc_header)))) {
    memset((void *)header, 0, sizeof(llc_header));

    header->dsap = LLC_SNAP;
    header->ssap = LLC_SNAP;
    header->control_field = UNNUMBERED_FRAME;
    header->type = __cpu_to_be16(DOT1X_AUTHENTICATION);
  }

  return header;
}

ieee802dot1x_header *build_ieee802dot1x_header(uint8_t type,
                                               uint16_t payload_len) {
  ieee802dot1x_header *header = NULL;
  if ((header = (ieee802dot1x_header *)malloc(sizeof(ieee802dot1x_header)))) {
    memset((void *)header, 0, sizeof(ieee802dot1x_header));

    header->version = DOT1X_VERSION;
    header->type = type;
    header->length = htons(payload_len);
  }

  return header;
}

eap_header *build_eap_header(uint8_t id, uint8_t code, uint8_t type,
                             uint16_t payload_len) {
  eap_header *header = NULL;
  if ((header = malloc(sizeof(eap_header)))) {
    memset((void *)header, 0, sizeof(eap_header));

    header->code = code;
    header->id = id;
    header->length = htons(payload_len + sizeof(eap_header));
    header->type = type;

    id++;
  }

  return header;
}

wfa_expanded_header *build_wfa_header(uint8_t op_code) {
  wfa_expanded_header *header = NULL;
  if ((header = malloc(sizeof(wfa_expanded_header)))) {
    memset((void *)header, 0, sizeof(wfa_expanded_header));

    memcpy(header->id, WFA_VENDOR_ID, sizeof(header->id));
    header->type = __cpu_to_be32(SIMPLE_CONFIG);
    header->opcode = op_code;
  }

  return header;
}
