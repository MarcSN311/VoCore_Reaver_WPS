#ifndef HEADERS_H
#define HEADERS_H

#include <linux/byteorder/little_endian.h>
#include <malloc.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define DEFAULT_DURATION 52
#define DOT1X_AUTHENTICATION 0x888E
#define LLC_SNAP 0xAA
#define UNNUMBERED_FRAME 0x03
#define DOT1X_VERSION 0x01
#define DOT1X_START 0x01
#define DOT1X_AUTHENTICATION 0x888E
#define DOT1X_EAP_PACKET 0x00
#define WFA_VENDOR_ID "\x00\x37\x2A"
#define WFA_REGISTRAR "WFA-SimpleConfig-Registrar-1-0"
#define SIMPLE_CONFIG 0x00000001

#define FC_ASSOCIATE 0x0000
#define FC_AUTHENTICATE 0x00B0
#define FC_STANDARD 0x0108
#define FC_DEAUTHENTICATE 0x00C0
#define LISTEN_INTERVAL 0x0064
#define OPEN_SYSTEM 0

#define DEAUTH_REASON_CODE "\x03\x00"
#define DEAUTH_REASON_CODE_SIZE 2

#define EAP_IDENTITY 0x01
#define EAP_EXPANDED 0xFE

enum eap_codes {
  EAP_REQUEST = 1,
  EAP_RESPONSE = 2,
  EAP_SUCCESS = 3,
  EAP_FAILURE = 4
};

// Structures to easily manage WiFi Headers
#pragma pack(1)

typedef struct { uint8_t byte[6]; } MAC;

typedef struct {
  MAC addr1;
  MAC addr2;
  MAC addr3;
} macpack;

typedef struct {
  uint8_t revision;
  uint8_t pad;
  uint16_t length;
  uint32_t flags;
} radiotap_header;

typedef struct {
  uint16_t framecontrol;
  uint16_t duration;
  MAC addr1;
  MAC addr2;
  MAC addr3;
  uint16_t seqnum;
} ieee802dot11_header;

typedef struct {
  uint8_t dsap;
  uint8_t ssap;
  uint8_t control_field;
  uint8_t org_code[3];
  uint16_t type;
} llc_header;

typedef struct {
  uint8_t version;
  uint8_t type;
  uint16_t length;
} ieee802dot1x_header;

typedef struct {
  uint8_t code;
  uint8_t id;
  uint16_t length;
  uint8_t type;
} eap_header;

typedef struct {
  uint8_t id[3];
  uint32_t type;
  uint8_t opcode;
  uint8_t flags;
} wfa_expanded_header;

typedef struct {
  uint16_t type;
  uint16_t length;
} wfa_element_header;

typedef struct {
  uint16_t algorithm;
  uint16_t sequence;
  uint16_t status;
} authentication_management_frame;

typedef struct {
  uint16_t capability;
  uint16_t listen_interval;
} association_request_management_frame;

typedef struct {
  uint16_t capability;
  uint16_t status;
  uint16_t id;
} association_response_management_frame;

#pragma pack()

radiotap_header *build_radiotap_header();

ieee802dot11_header *build_ieee802dot11_header(uint16_t framecontrol, MAC addr1,
                                               MAC addr2, MAC addr3);

llc_header *build_llc_header();

ieee802dot1x_header *build_ieee802dot1x_header(uint8_t type,
                                               uint16_t payload_len);

eap_header *build_eap_header(uint8_t id, uint8_t code, uint8_t type,
                             uint16_t payload_len);

wfa_expanded_header *build_wfa_header(uint8_t op_code);

#endif
