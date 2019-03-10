#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <iomanip>
#include <sstream>
#include "ArpScanner.h"
#include "RadiotapScanner.h"
extern "C"{
    #include <pcap.h>
    #include <string.h>
    #include "radiotap_iter.h"
    #include <machine/endian.h>
    #if defined(__APPLE__)
    #else
    #include <endian.h>
    #endif
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <err.h>
 //   #include <dumbnet.h>
    #include <dnet.h>

}

int main(int argc, char *argv[]){

  //  char *device, errbuf[PCAP_ERRBUF_SIZE];
  //  pcap_t *handle;
    //char filter[]="type mgt subtype beacon";
    //char filter[] = "type data";
  //  char filter[]="type mgt or type ctl or type data";
  //  struct bpf_program fp;

  //  bpf_u_int32 mask;
  //  bpf_u_int32 network;

  if(argc==1){
    RadiotapScanner *scanner = new RadiotapScanner();
    scanner->startScan();
    scanner->close();
  }

  else if(argc==2){
    printf("Due argomenti");
    RadiotapScanner *scanner = new RadiotapScanner(argv[1]);
    return 0;
  }

  else{
    return 1;
  }
}
