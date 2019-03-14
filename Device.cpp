#include "Device.h"
#include <iostream>

Device::Device(std::string mac){
  isAP=false;
  mac_address=mac;
}

void Device::setAP(u_int8_t length, char *ssidp){
  isAP=true;
  ssid = new char[length];
  memcpy(ssid,ssidp,length);
}

void Device::setIP(std::string ip){
  ip_address=ip;
}

void Device::Print(){
  if(isAP){
    std::cout << "******************************************" << std::endl;

    std::cout << " AP con Mac Address:" << mac_address << std::endl;
      std::cout << "SSID:" << ssid << std::endl;
      //std::cout << "Power segment - Signal : " << power.antenna_signal << "Noise : " << power.antenna_noise << "Timestamp: " << power.timestamp;
      printf("\tSignal : %d\n",(signed char) power.antenna_signal);
      printf("\tNoise : %d\n",(signed char) power.antenna_noise);
      printf("\tChannel : %d\n", power.channel);

  std::cout << "Sto parlando con : " << std::endl;
  for(unsigned long i = 0 ; i < talkers.size() ; i++){
    std::cout << talkers[i] << std::endl;
/*
    auto search = devices.find(talkers[i]);
    if(search != devices.end()){
      struct signal_power toprint = search->second->returnPowerValues();
      printf(" che ha signal : %d\t",(signed char) toprint.antenna_signal);
      printf(" e noise : %d\n",(signed char) toprint.antenna_noise);
    }
    else{
      std::cout << "Non trovato";
    }*/
  }
  std::cout << "******************************************" << std::endl;

}
}/*
  else{
    std::cout << "Device con Mac Address: " << mac_address;
    printf("\t Signal : %d",(signed char) power.antenna_signal);
    printf("\t Noise : %d\n",(signed char) power.antenna_noise);
  }
}*/

std::string Device::getDeviceMAC(){
  return mac_address;
}

char * Device::getDeviceSSID(){
  return ssid;
}

std::string Device::getDeviceIP(){
  return ip_address;
}

bool Device::isTalking(std::string dev_mac){
  std::cout << "Dentro istalking";
  for(unsigned long i=0; i < talkers.size() ; i++){
      if(talkers[i]==dev_mac){
          return true;
      }
  }
  return false;
}

void Device::addTalker(std::string dev_mac){
  std::cout << "Dentro addtalker";
  talkers.push_back(dev_mac);
}

void Device::addPowerValues(struct signal_power p){
  power.antenna_signal=p.antenna_signal;
  power.antenna_noise=p.antenna_noise;
  power.timestamp=p.timestamp;
  power.channel=p.channel;
}

struct signal_power Device::returnPowerValues(){
  return power;
}
