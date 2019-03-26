#include "Pinger.h"

Pinger::Pinger(){
  me=this;
  socketfd = socket(PF_INET,SOCK_RAW,1);
  if(socketfd<0){
    std::cout << "Errore";
    //Chiudere
  }
}

void Pinger::createPacket(icmp_hdr_t* pckt){
  pckt->type = 8;
  pckt->code = 0;
  pckt->chksum = 0xfff7;
  //pckt->icmp_seq = ntransmitted++;
  pckt->data = 0;
}

void Pinger::startPing(std::string ip){
  me=this;
  nreceived=0;
  ntransmitted=0;
  sendPacket(ip);
  receivePacket();
  statistics();
}

void Pinger::sendPacket(std::string ip){
  while(ntransmitted<MAXPACKETS){
    icmp_hdr_t pckt;
    createPacket(&pckt);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    addr.sin_addr.s_addr = inet_addr(ip.c_str());
    //inet_aton(ip.c_str(), &addr.sin_addr.s_addr);

    if(addr.sin_addr.s_addr==0){
      return;
    }
    //inet_pton(AF_INET, ip, &(addr.sin_addr.s_addr));
    gettimeofday(&start[ntransmitted], NULL);
    int r= sendto(socketfd, &pckt, sizeof(pckt),0, (struct sockaddr*)&addr, sizeof(addr));
    if(r < 0){
      std::cout << "Errore ping" << std::endl;
      return;
    }
    ntransmitted++;
  }
}

void Pinger::receivePacket(){
  unsigned int resAddressSize;
  unsigned char res[30] = "";
  struct sockaddr resAddress;
  signal(SIGALRM,Pinger::handler);
  while(nreceived<ntransmitted){
    alarm(MAXWAIT);
  int r = recvfrom(socketfd, res, sizeof(res), 0, &resAddress, &resAddressSize);

  if(r > 0){
    icmp_response_t* echo_response;
    echo_response = (icmp_response_t *)&res[20];
    gettimeofday(&end[nreceived], NULL);
    end_t[nreceived] = 1000000*((double)(end[nreceived].tv_sec - start[nreceived].tv_sec)) + ((double)(end[nreceived].tv_usec - start[nreceived].tv_usec))/1000;
    std::cout << "Tempo trascorso = " << end_t[nreceived] << " msec" << std::endl;
    nreceived++;
  }
  else{
    std::cout << "Errore risposta" <<std::endl;
  }
}
}

void Pinger::Destroy(){
  close(socketfd);
}

void Pinger::handler(int signo){
  me->statistics();
}

void Pinger::statistics(){

    printf("\n--------------------PING-------------------\n");

    printf("%d trasmessi, %d ricevuti , %%%d persi\n", ntransmitted,

        nreceived, (ntransmitted - nreceived) / ntransmitted * 100);

    close(socketfd);

    exit(1);
}
