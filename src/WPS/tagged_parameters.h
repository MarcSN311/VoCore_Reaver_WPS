#ifndef TAGGED_PARAMETERS_H
#define TAGGED_PARAMETERS_H

#include <malloc.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define WPS_TAG_NUMBER 0xDD
#define WPS_TAG_SIZE 14
#define WPS_REGISTRAR_TAG                                                      \
  "\x00\x50\xF2\x04\x10\x4A\x00\x01\x10\x10\x3A\x00\x01\x02"
/*
 * oui					[{Microsoft}\x00\x50\xF2](3)
 * Type					[{WPS}\x04](1)
 * Version			[{Version Header}\x10\x4A
 *               {LEN:1}\x00\x01
 *               {Value:}\x10](5)
 * Request Type	[{Request Type Header}\x10\x3A
 *               {LEN:1}\x00\x01
 *               {Value:Registrar}\x02](5)
 * Tell the AP we are a registrar and we use WPS version 0x10
 */

#define SSID_TAG_NUMBER 0
#define ERATES_TAG_SIZE 4
#define SRATES_TAG_NUMBER 0x01
#define ERATES_TAG_NUMBER 0x32
#define WPS_TAG_SIZE 14
#define WPS_REGISTRAR_TAG                                                      \
  "\x00\x50\xF2\x04\x10\x4A\x00\x01\x10\x10\x3A\x00\x01\x02"
#define EXTENDED_RATES_TAG "\x30\x48\x60\x6C"

#pragma pack(1)
typedef struct {
  uint8_t number;
  uint8_t len;
} tagged_parameter;
#pragma pack()

tagged_parameter *build_tagged_parameter(uint8_t number, uint8_t size);

tagged_parameter *build_ssid_tagged_parameter(char *ssid);

tagged_parameter *build_wps_tagged_parameter();

tagged_parameter *
build_supported_rates_tagged_parameter(uint8_t *srates, size_t srates_tag_size);

#endif
