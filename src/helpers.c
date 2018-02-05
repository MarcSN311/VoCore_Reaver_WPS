#include "helpers.h"

void printip(bpf_u_int32 ip) {
  printf("%d.%d.%d.%d", ((unsigned char *)&ip)[0], ((unsigned char *)&ip)[1],
         ((unsigned char *)&ip)[2], ((unsigned char *)&ip)[3]);
}

void printMAC(MAC *m) {
  int i = 0;
  for (i = 0; i < 6; ++i)
    printf(" %02x", ((uint8_t *)m)[i]);
  printf("\n");
}

void printpacket(const unsigned char *p, int len) {
  int i = 0;
  while (i < len) {
    printf("%02x ", *(p++));
    if (!(++i % 16))
      printf("\n");
  }
  printf("\n");
}

MAC *getMAC() {
  struct ifreq s;
  int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
  MAC *mymac = NULL;
  strcpy(s.ifr_name, "wlan0");

  if ((mymac = malloc(sizeof(MAC)))) {
    memset((void *)mymac, 0, sizeof(MAC));
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
      memcpy((void *)mymac, s.ifr_addr.sa_data, sizeof(MAC));
    }
  }
  return mymac;
}

int get_random(unsigned char *buf, size_t len) {
  FILE *f;
  size_t rc;

  f = fopen("/dev/urandom", "rb");
  if (f == NULL) {
    printf("Could not open /dev/urandom.\n");
    return -1;
  }

  rc = fread(buf, 1, len, f);
  fclose(f);

  return rc != len ? -1 : 0;
}

void *zalloc(size_t size) {
  void *n = malloc(size);
  if (n)
    memset(n, 0, size);
  return n;
}
