#include "keyexchange.h"

// WPS Attributes
// 0xFF00 : 'Vendor',
// 0xFF01 : 'Vendor Type',
// 0xFF02 : 'Opcode',
// 0xFF03 : 'Flags',
// 0x104A : 'Version',
// 0x104A : 'Authentication Flags',
// 0x1022 : 'Message Type',
// 0x1047 : 'UUID E',
// 0x1020 : 'MAC',
// 0x101a : 'Enrollee Nonce',
// 0x1032 : 'Public Key',
// 0x1010 : 'Encryption Type Flags',
// 0x100d : 'Connection Type Flags',
// 0x1008 : 'Config Methods',
// 0x100d : 'Wifi Protected Setup State',
// 0x1021 : 'Manufacturer',
// 0x1023 : 'Model Name',
// 0x1024 : 'Model Number',
// 0x1042 : 'Serial Number',
// 0x1054 : 'Primary Device Type',
// 0x1011 : 'Device Name',
// 0x103c : 'RF Bands',
// 0x1002 : 'Association State',
// 0x1012 : 'Device pin',
// 0x1009 : 'Configuration Error',
// 0x102d : 'OS Version',
// 0x1044 : 'Wifi Protected Setup State',
// 0x1004 : 'Authentication Type',
// 0x1005 : 'Authenticator',
// 0x1048 : 'UUID R',
// 0x1039 : 'Registrar Nonce',
// 0x1014 : 'E Hash 1',
// 0x1015 : 'E Hash 2',
// 0x103D : 'R Hash 2',
// 0x103E : 'R Hash 2',
// 0x1018 : 'Encrypted Settings',
// 0x103F : 'R-S1',
// 0x101e : 'Key Wrap Algorithm',
// 0x1016 : 'E-S1',
// 0x1017 : 'E-S2',
// 0x1003 : 'Auth Type',
// 0x100F : 'Encryption Type',
// 0x1003 : 'Auth Type',
// 0x1027 : 'Network Key',
// 0x1028 : 'Network Key Index',
// 0x1045 : 'SSID'

void wps_kdf(const uint8_t *key, const uint8_t *label_prefix,
             size_t label_prefix_len, const char *label, uint8_t *res,
             size_t res_len) {
  uint32_t i_buf;
  uint32_t key_bits;
  const uint8_t *addr[4];
  size_t len[4];
  int i, iter;
  uint8_t hash[SHA256_MAC_LEN], *opos;
  size_t left;

  key_bits = bswap_32(res_len * 8);

  addr[0] = (uint8_t *)&i_buf;
  len[0] = sizeof(i_buf);
  addr[1] = label_prefix;
  len[1] = label_prefix_len;
  addr[2] = (const uint8_t *)label;
  len[2] = strlen(label);
  addr[3] = (uint8_t *)&key_bits;
  len[3] = sizeof(key_bits);

  iter = (res_len + SHA256_MAC_LEN - 1) / SHA256_MAC_LEN;
  opos = res;
  left = res_len;

  for (i = 1; i <= iter; i++) {
    i_buf = bswap_32(i);
    hmac_sha256_vector(key, SHA256_MAC_LEN, 4, addr, len, hash);
    if (i < iter) {
      memcpy(opos, hash, SHA256_MAC_LEN);
      opos += SHA256_MAC_LEN;
      left -= SHA256_MAC_LEN;
    } else
      memcpy(opos, hash, left);
  }
}

eap_header *create_wfa_element(eap_header *eap, uint16_t type, uint16_t length,
                               char *payload) {
  if (eap == NULL) {
    fprintf(stderr, "Failed! eap ist null!\n");
    return NULL;
  }
  size_t eaplen = ntohs(eap->length);

  eap_header *neweap =
      realloc(eap, eaplen + sizeof(wfa_element_header) + length);
  if (neweap == NULL) {
    fprintf(stderr, "Failed to allocate memory!\n");
    return NULL;
  }

  wfa_element_header *wfa =
      (wfa_element_header *)(((uint8_t *)neweap) + eaplen);
  wfa->length = htons(length);
  wfa->type = htons(type);
  memcpy(((uint8_t *)wfa) + sizeof(*wfa), payload, length);

  neweap->length = htons(eaplen + sizeof(*wfa) + length);

  return neweap;
}

void send_m2(pcap_t *handle, WPSDATA *data, MAC addr1, MAC addr2, MAC addr3) {
  uint8_t hash[SHA256_MAC_LEN];
  const uint8_t *addr[2];
  size_t len[2];
  radiotap_header *radio_tap = NULL;
  ieee802dot11_header *dot11_frame = NULL;
  llc_header *llc = NULL;
  ieee802dot1x_header *dot1x = NULL;
  wfa_expanded_header *wfa = NULL;
  eap_header *eap = NULL;
  unsigned char *packet = NULL;
  size_t packet_len = 0, offset = 0, eap_len = 0;

  radio_tap = build_radiotap_header();
  dot11_frame = build_ieee802dot11_header(FC_STANDARD, addr1, addr2, addr3);
  llc = build_llc_header();
  wfa = build_wfa_header(0x04);
  eap = build_eap_header(1, EAP_RESPONSE, 0xfe, sizeof(wfa_expanded_header));
  eap = create_wfa_element(eap, 0x104a, 1, "\x10");
  eap = create_wfa_element(eap, 0x1022, 1, "\x05");
  eap = create_wfa_element(eap, 0x101a, 16, (char *)data->n1);
  eap = create_wfa_element(eap, 0x1039, 16, (char *)data->n2);
  eap = create_wfa_element(
      eap, 0x1048, 16,
      "\x8f\xb9\x07\xac\xb4\x94\x6d\x00\xed\x3e\xab\x39\xf5\xed\xb2\x9d");
  eap = create_wfa_element(eap, 0x1032, 192, (char *)data->pkr);
  eap = create_wfa_element(eap, 0x1004, 2, "\x00\x3f");
  eap = create_wfa_element(eap, 0x1010, 2, "\x00\x0f");
  eap = create_wfa_element(eap, 0x100d, 1, "\x01");
  eap = create_wfa_element(eap, 0x1008, 2, "\x01\x08");
  eap = create_wfa_element(eap, 0x1021, 1, "\x00");
  eap = create_wfa_element(eap, 0x1023, 1, "\x00");
  eap = create_wfa_element(eap, 0x1024, 1, "\x00");
  eap = create_wfa_element(eap, 0x1042, 1, "\x00");
  eap = create_wfa_element(eap, 0x1054, 8, "\x00\x00\x00\x00\x00\x00\x00\x00");
  eap = create_wfa_element(eap, 0x1011, 1, "\x00");
  eap = create_wfa_element(eap, 0x103c, 1, "\x03");
  eap = create_wfa_element(eap, 0x1002, 2, "\x00\x00");
  eap = create_wfa_element(eap, 0x1009, 2, "\x00\x00");
  eap = create_wfa_element(eap, 0x1012, 2, "\x00\x00");
  eap = create_wfa_element(eap, 0x102d, 4, "\x80\x00\x00\x00");
  eap = create_wfa_element(eap, 0x1005, 8, "\x00\x00\x00\x00\x00\x00\x00\x00");
  eap_len = ntohs(eap->length);
  dot1x = build_ieee802dot1x_header(DOT1X_EAP_PACKET, eap_len);

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
      memcpy(((uint8_t *)eap) + sizeof(*eap), wfa, sizeof(*wfa));
      memcpy(packet + offset, eap, eap_len);

      addr[0] = data->last_msg;
      len[0] = data->last_msg_len;
      addr[1] = packet + offset + sizeof(*eap) + sizeof(*wfa);
      len[1] = eap_len - 12 - sizeof(*eap) - sizeof(*wfa);

      hmac_sha256_vector(data->authkey, 32, 2, addr, len, hash);
      memcpy(packet + packet_len - 8, hash, 8);

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
  if (wfa)
    free(wfa);
  if (eap)
    free(eap);
  return;
}

void send_m4(pcap_t *handle, WPSDATA *data, MAC addr1, MAC addr2, MAC addr3) {
  uint8_t hash[SHA256_MAC_LEN];
  const uint8_t *addr[2];
  size_t len[2];
  radiotap_header *radio_tap = NULL;
  ieee802dot11_header *dot11_frame = NULL;
  llc_header *llc = NULL;
  ieee802dot1x_header *dot1x = NULL;
  wfa_expanded_header *wfa = NULL;
  eap_header *eap = NULL;
  unsigned char *packet = NULL;
  size_t packet_len = 0, offset = 0, eap_len = 0;

  radio_tap = build_radiotap_header();
  dot11_frame = build_ieee802dot11_header(FC_STANDARD, addr1, addr2, addr3);
  llc = build_llc_header();
  wfa = build_wfa_header(0x04);
  eap = build_eap_header(2, EAP_RESPONSE, 0xfe, sizeof(wfa_expanded_header));
  eap = create_wfa_element(eap, 0x104a, 1, "\x10");
  eap = create_wfa_element(eap, 0x1022, 1, "\x08");
  eap = create_wfa_element(eap, 0x101a, 16, (char *)data->n1);
  eap = create_wfa_element(eap, 0x103d, 32, (char *)data->rhash1);
  eap = create_wfa_element(eap, 0x103e, 32, (char *)data->rhash2);
  eap = create_wfa_element(eap, 0x1018, 64, (char *)data->rs1);
  eap = create_wfa_element(eap, 0x1005, 8, "\x00\x00\x00\x00\x00\x00\x00\x00");
  eap_len = ntohs(eap->length);
  dot1x = build_ieee802dot1x_header(DOT1X_EAP_PACKET, eap_len);

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
      memcpy(((uint8_t *)eap) + sizeof(*eap), wfa, sizeof(*wfa));
      memcpy(packet + offset, eap, eap_len);

      addr[0] = data->last_msg;
      len[0] = data->last_msg_len;
      addr[1] = packet + offset + sizeof(*eap) + sizeof(*wfa);
      len[1] = eap_len - 12 - sizeof(*eap) - sizeof(*wfa);

      hmac_sha256_vector(data->authkey, 32, 2, addr, len, hash);
      memcpy(packet + packet_len - 8, hash, 8);

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
  if (wfa)
    free(wfa);
  if (eap)
    free(eap);
  return;
}

void send_m6(pcap_t *handle, WPSDATA *data, MAC addr1, MAC addr2, MAC addr3) {
  uint8_t hash[SHA256_MAC_LEN];
  const uint8_t *addr[2];
  size_t len[2];
  radiotap_header *radio_tap = NULL;
  ieee802dot11_header *dot11_frame = NULL;
  llc_header *llc = NULL;
  ieee802dot1x_header *dot1x = NULL;
  wfa_expanded_header *wfa = NULL;
  eap_header *eap = NULL;
  unsigned char *packet = NULL;
  size_t packet_len = 0, offset = 0, eap_len = 0;

  radio_tap = build_radiotap_header();
  dot11_frame = build_ieee802dot11_header(FC_STANDARD, addr1, addr2, addr3);
  llc = build_llc_header();
  wfa = build_wfa_header(0x04);
  eap = build_eap_header(3, EAP_RESPONSE, 0xfe, sizeof(wfa_expanded_header));
  eap = create_wfa_element(eap, 0x104a, 1, "\x10");
  eap = create_wfa_element(eap, 0x1022, 1, "\x0a");
  eap = create_wfa_element(eap, 0x101a, 16, (char *)data->n1);
  eap = create_wfa_element(eap, 0x1018, 64, (char *)data->rs2);
  eap = create_wfa_element(eap, 0x1005, 8, "\x00\x00\x00\x00\x00\x00\x00\x00");
  eap_len = ntohs(eap->length);
  dot1x = build_ieee802dot1x_header(DOT1X_EAP_PACKET, eap_len);

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
      memcpy(((uint8_t *)eap) + sizeof(*eap), wfa, sizeof(*wfa));
      memcpy(packet + offset, eap, eap_len);

      addr[0] = data->last_msg;
      len[0] = data->last_msg_len;
      addr[1] = packet + offset + sizeof(*eap) + sizeof(*wfa);
      len[1] = eap_len - 12 - sizeof(*eap) - sizeof(*wfa);

      hmac_sha256_vector(data->authkey, 32, 2, addr, len, hash);
      memcpy(packet + packet_len - 8, hash, 8);

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
  if (wfa)
    free(wfa);
  if (eap)
    free(eap);
  return;
}

void send_wsc_nack(pcap_t *handle, uint8_t wsc_id, WPSDATA *data, MAC addr1,
                   MAC addr2, MAC addr3) {
  radiotap_header *radio_tap = NULL;
  ieee802dot11_header *dot11_frame = NULL;
  llc_header *llc = NULL;
  ieee802dot1x_header *dot1x = NULL;
  wfa_expanded_header *wfa = NULL;
  eap_header *eap = NULL;
  unsigned char *packet = NULL;
  size_t packet_len = 0, offset = 0, eap_len = 0;

  radio_tap = build_radiotap_header();
  dot11_frame = build_ieee802dot11_header(FC_STANDARD, addr1, addr2, addr3);
  llc = build_llc_header();
  wfa = build_wfa_header(0x03);
  eap =
      build_eap_header(wsc_id, EAP_RESPONSE, 0xfe, sizeof(wfa_expanded_header));
  eap = create_wfa_element(eap, 0x104a, 1, "\x10");
  eap = create_wfa_element(eap, 0x1022, 1, "\x0e");
  eap = create_wfa_element(eap, 0x101a, 16, (char *)data->n1);
  eap = create_wfa_element(eap, 0x1039, 16, (char *)data->n2);
  eap = create_wfa_element(eap, 0x1009, 2, "\x00\x00");
  eap_len = ntohs(eap->length);
  dot1x = build_ieee802dot1x_header(DOT1X_EAP_PACKET, eap_len);

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
      memcpy(((uint8_t *)eap) + sizeof(*eap), wfa, sizeof(*wfa));
      memcpy(packet + offset, eap, eap_len);

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
  if (wfa)
    free(wfa);
  if (eap)
    free(eap);
  return;
}

// precalculate all crypto stuff
int wps_build_key(WPSDATA *data, uint8_t *wpspin) {
  struct wpabuf *dh_privkey = NULL, *pk_r = NULL,
                *pk_e = wpabuf_alloc_ext_data(data->pke, 192), *dh_shared;
  uint8_t dhkey[32], kdk[32], keys[32 + 16 + 32], hash[SHA256_MAC_LEN],
      encbuffer[48];
  const uint8_t *addr[4];
  size_t len[4];

  // Generate DH Keypair
  data->dh_ctx = dh5_init(&dh_privkey, &pk_r);
  pk_r = wpabuf_zeropad(pk_r, 192);

  if (data->dh_ctx == NULL || dh_privkey == NULL || pk_r == NULL) {
    fprintf(stderr, "WPS: Failed to initialize Diffie-Hellman handshake");
    return -1;
  }

  // save our public key
  memcpy(data->pkr, wpabuf_head(pk_r), 192);

  // Calculating Diffie-Hellman shared secret
  dh_shared = dh5_derive_shared(data->dh_ctx, pk_e, dh_privkey);
  dh_shared = wpabuf_zeropad(dh_shared, 192);

  // HMAC DH shared secret: DHKey = SHA-256(g^AB mod p)
  addr[0] = wpabuf_head(dh_shared);
  len[0] = wpabuf_len(dh_shared);
  sha256_vector(1, addr, len, dhkey);

  // Generate our Nonce
  get_random(data->n2, 16);

  // Create Key Derivation Key: KDK = HMAC-SHA-256_DHKey(N1 || EnrolleeMAC ||
  // N2)
  addr[0] = data->n1;
  len[0] = 16;
  addr[1] = data->mac.byte;
  len[1] = 6;
  addr[2] = data->n2;
  len[2] = 16;
  hmac_sha256_vector(dhkey, sizeof(dhkey), 3, addr, len, kdk);

  // Derive Keys
  wps_kdf(kdk, NULL, 0, "Wi-Fi Easy and Secure Key Derivation", keys,
          sizeof(keys));
  memcpy(data->authkey, keys, 32);
  memcpy(data->keywrapkey, keys + 32, 16);
  memcpy(data->emsk, keys + 32 + 16, 32);

  // calculate plain PSKs
  hmac_sha256(data->authkey, 32, wpspin, 4, hash);
  memcpy(data->psk1, hash, 16);
  hmac_sha256(data->authkey, 32, wpspin + 4, 4, hash);
  memcpy(data->psk2, hash, 16);

  // RS-1, RS-2 and iv don't neet to be secure, so we can just use zeros
  memset(data->plain_rs1, 0, 16);
  memset(data->plain_rs2, 0, 16);
  memset(data->iv, 0, 16);

  // calculate R-Hash1 = HMAC_AuthKey(R-S1 || PSK1 || PK_E || PK_R)
  addr[0] = data->plain_rs1;
  len[0] = 16;
  addr[1] = data->psk1;
  len[1] = 16;
  addr[2] = data->pke;
  len[2] = 192;
  addr[3] = data->pkr;
  len[3] = 192;
  hmac_sha256_vector(data->authkey, 32, 4, addr, len, hash);
  memcpy(data->rhash1, hash, 32);

  // calculate R-Hash2 = HMAC_AuthKey(R-S2 || PSK2 || PK_E || PK_R)
  addr[0] = data->plain_rs2;
  len[0] = 16;
  addr[1] = data->psk2;
  len[1] = 16;
  addr[2] = data->pke;
  len[2] = 192;
  addr[3] = data->pkr;
  len[3] = 192;
  hmac_sha256_vector(data->authkey, 32, 4, addr, len, hash);
  memcpy(data->rhash2, hash, 32);

  // create so called "Encrypted Settings" Block containing our secret key RS-1
  memset(encbuffer, 0, 48);
  memcpy(encbuffer, "\x10\x3f\x00\x10", 4);
  memcpy(encbuffer + 4, data->plain_rs1, 16);
  addr[0] = encbuffer;
  len[0] = 20;
  hmac_sha256_vector(data->authkey, 32, 1, addr, len, hash);
  memcpy(encbuffer + 20, "\x10\x1e\x00\x08", 4);
  memcpy(encbuffer + 24, hash, 8);
  aes_128_cbc_encrypt(data->keywrapkey, data->iv, encbuffer, 48);
  memcpy(data->rs1, data->iv, 16);
  memcpy(data->rs1 + 16, encbuffer, 48);

  // create so called "Encrypted Settings" Block containing our secret key RS-2
  memset(encbuffer, 0, 48);
  memcpy(encbuffer, "\x10\x40\x00\x10", 4);
  memcpy(encbuffer + 4, data->plain_rs2, 16);
  addr[0] = encbuffer;
  len[0] = 20;
  hmac_sha256_vector(data->authkey, 32, 1, addr, len, hash);
  memcpy(encbuffer + 20, "\x10\x1e\x00\x08", 4);
  memcpy(encbuffer + 24, hash, 8);
  aes_128_cbc_encrypt(data->keywrapkey, data->iv, encbuffer, 48);
  memcpy(data->rs2, data->iv, 16);
  memcpy(data->rs2 + 16, encbuffer, 48);

  return 0;
}
