#ifndef AUTHENTICATE_H
#define AUTHENTICATE_H

#include "../send.h"
#include "headers.h"

authentication_management_frame *build_authentication_management_frame();

void deauthenticate(pcap_t *handle, MAC addr1, MAC addr2, MAC addr3);
void authenticate(pcap_t *handle, MAC addr1, MAC addr2, MAC addr3);

#endif
