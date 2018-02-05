#include "tagged_parameters.h"

tagged_parameter *build_tagged_parameter(uint8_t number, uint8_t size) {
  tagged_parameter *param = malloc(sizeof(tagged_parameter));
  if (param) {
    param->number = number;
    param->len = size;
  }
  return param;
}

tagged_parameter *build_ssid_tagged_parameter(char *ssid) {
  void *buf = NULL;
  tagged_parameter *ssid_param = NULL;
  size_t ssid_len = 0, buf_len = 0;

  if (ssid) {
    ssid_len = strlen(ssid);
  }

  ssid_param = build_tagged_parameter(SSID_TAG_NUMBER, ssid_len);

  if (ssid_param) {
    buf_len = sizeof(tagged_parameter) + ssid_len;
    if ((buf = malloc(buf_len))) {
      memset((void *)buf, 0, buf_len);

      memcpy((void *)buf, ssid_param, sizeof(tagged_parameter));
      memcpy((void *)((char *)buf + sizeof(tagged_parameter)), ssid, ssid_len);
    }

    free((void *)ssid_param);
  }

  return buf;
}

tagged_parameter *build_wps_tagged_parameter() {
  void *buf = NULL;
  tagged_parameter *wps_param = NULL;
  size_t buf_len = 0;

  wps_param = build_tagged_parameter(WPS_TAG_NUMBER, WPS_TAG_SIZE);

  if (wps_param) {
    buf_len = sizeof(tagged_parameter) + WPS_TAG_SIZE;
    if ((buf = malloc(buf_len))) {
      memset((void *)buf, 0, buf_len);

      memcpy((void *)buf, wps_param, sizeof(tagged_parameter));
      memcpy((void *)((char *)buf + sizeof(tagged_parameter)),
             WPS_REGISTRAR_TAG, WPS_TAG_SIZE);
    }

    free((void *)wps_param);
  }

  return buf;
}

tagged_parameter *
build_supported_rates_tagged_parameter(uint8_t *srates,
                                       size_t srates_tag_size) {
  void *buf = NULL;
  tagged_parameter *supported_rates = NULL, *extended_rates = NULL;
  size_t buf_len = 0, offset = 0;

  supported_rates = build_tagged_parameter(SRATES_TAG_NUMBER, srates_tag_size);
  extended_rates = build_tagged_parameter(ERATES_TAG_NUMBER, ERATES_TAG_SIZE);

  if (supported_rates && extended_rates) {
    buf_len = sizeof(*supported_rates) + sizeof(*extended_rates) +
              srates_tag_size + ERATES_TAG_SIZE;
    if ((buf = malloc(buf_len))) {
      memset((void *)buf, 0, buf_len);

      memcpy((void *)buf, supported_rates, sizeof(*supported_rates));
      offset += sizeof(*supported_rates);
      memcpy((void *)((char *)buf + offset), srates, srates_tag_size);
      offset += srates_tag_size;
      memcpy((void *)((char *)buf + offset), extended_rates,
             sizeof(*extended_rates));
      offset += sizeof(*extended_rates);
      memcpy((void *)((char *)buf + offset), EXTENDED_RATES_TAG,
             ERATES_TAG_SIZE);
    }
  }

  if (supported_rates)
    free((void *)supported_rates);
  if (extended_rates)
    free((void *)extended_rates);

  return buf;
}
