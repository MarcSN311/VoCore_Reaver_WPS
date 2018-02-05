#ifndef WPSTRANSACTION_H
#define WPSTRANSACTION_H

#include <pcap.h>
// needed for timeouts
#include <signal.h>
#include <unistd.h>
// all the package send functions
#include "associate.h"
#include "authenticate.h"
#include "eap.h"
#include "keyexchange.h"

int doexchange(pcap_t *handle, char *targetssid, uint8_t *wpspin, MAC *mymac);

#endif
