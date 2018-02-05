#ifndef ASSOCIATE_H
#define ASSOCIATE_H

#include "../send.h"
#include "headers.h"
#include "tagged_parameters.h"

void associate(pcap_t *handle, char *ssid, uint8_t *srates,
               size_t srates_tag_size, MAC addr1, MAC addr2, MAC addr3);

#endif
