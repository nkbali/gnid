#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if_dl.h>
#include <ifaddrs.h>
#include <stdlib.h>
#include <string.h>

#include "openssl/sha.h"
#define BUFSIZE 128
#define COMBINEDBUFSIZE 2048


int computeSHA256(char ptr[]){
char buf[BUFSIZE];
    FILE *fp;
char command[BUFSIZE];
snprintf(command, BUFSIZE, "echo -n \"%s\" | openssl sha256 | tr -d '(stdin)= '", ptr);
    if ((fp = popen(command, "r")) == NULL) {
        printf("Error opening pipe!\n");
        return -1;
    }

    while (fgets(buf, BUFSIZE, fp) != NULL) {
        printf("%s", buf);
    }

    if(pclose(fp))  {
        printf("Command not found or exited with error status\n");
        return -1;
    }

return 0;
}

int listmacaddrs(void) {
    struct ifaddrs *ifap, *ifaptr;
    unsigned char *ptr;
int index = 0;
char combinedMac[COMBINEDBUFSIZE];
    if (getifaddrs(&ifap) == 0) {
        for(ifaptr = ifap; ifaptr != NULL; ifaptr = (ifaptr)->ifa_next) {
            if (((ifaptr)->ifa_addr)->sa_family == AF_LINK && strcmp((ifaptr)->ifa_name, "lo0") != 0) {
                ptr = (unsigned char *)LLADDR((struct sockaddr_dl *)(ifaptr)->ifa_addr);
char mac[BUFSIZE];
snprintf(mac, BUFSIZE, "%02x:%02x:%02x:%02x:%02x:%02x",*ptr, *(ptr+1), *(ptr+2),
*(ptr+3), *(ptr+4), *(ptr+5));
if (index > 0){
strcat(combinedMac, "-");
}
index++;
strcat(combinedMac, mac);
            }
        }
        computeSHA256(combinedMac);
        freeifaddrs(ifap);
        return 1;
    } else {
        return 0;
    }
}

extern int
main(int argc, char* argv[]) {

    char macaddrstr[18];

   return  listmacaddrs();

}
