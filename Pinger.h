#include <string>
#include <iostream>
#define MAXPACKETS 3
#define MAXWAIT 3
extern "C"{
  #include <stdio.h>
  #include <stdlib.h>
  #include <arpa/inet.h>
  #include <sys/socket.h>
  #include <sys/time.h>
  #include <fcntl.h>
  #include <unistd.h>
  #include <netdb.h>
  #include <signal.h>
}

typedef struct {
    uint8_t type;
    uint8_t code;
    uint16_t chksum;
    uint32_t data;
} icmp_hdr_t;

typedef struct {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t sequence_number;
} icmp_response_t;

class Pinger{

public:
  struct timeval start[MAXPACKETS], end[MAXPACKETS];
  double end_t[MAXPACKETS];
  u_int8_t socketfd;
  int ntransmitted;
  int nreceived;

  Pinger();
  void createPacket(icmp_hdr_t* pckt);
  void sendPacket(std::string ip);
  void receivePacket();
  void startPing(std::string ip);
  void Destroy();
  static void handler(int signum);
  void statistics();

};
static Pinger* me;
