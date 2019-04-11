#include "Device.h"
#include <iostream>

Device::Device(std::string mac){
  isAP=false;
  mac_address=mac;
  main_device=NULL;
  power.antenna_signal=0;
  power.antenna_noise=0;
  isLocallyAdministered=checkLocalAdministered(mac_address);
}

Device::~Device(){
}

void Device::setAP(std::string ssidp){
  isAP=true;
  if(ssid!=ssidp){
    ssid=ssidp;
  }
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
/*
    std::cout << "Sto parlando con : " << std::endl;
  for(unsigned long i = 0 ; i < talkers.size() ; i++){
    std::cout << talkers[i];
    auto search = devices.find(talkers[i]);
    for(auto i : devices){
      std::cout<< i.first << std::endl;
    }
    if(search!=devices.end()){
      std::cout << search->first << " trovato " << std::endl;
      if(search->second->isLocallyAdministered){
        std::cout << "Sono locale" << std::endl;
        std::cout << "globally administered : "<< search->second->main_device->mac_address;
      }
    }
    else{
      std::cout << "Non trovato" << std::endl;
    }
    std::cout << std::endl; */
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
/*
  else{
    std::cout << "Device con Mac Address: " << mac_address;
    printf("\t Signal : %d",(signed char) power.antenna_signal);
    printf("\t Noise : %d\n",(signed char) power.antenna_noise);
  }
}*/

std::string Device::getDeviceMAC(){
  return mac_address;
}

std::string Device::getDeviceSSID(){
    return ssid;

}

std::string Device::getDeviceIP(){
  return ip_address;
}

bool Device::isTalking(std::string dev_mac){
  for(unsigned long i=0; i < talkers.size() ; i++){
      if(talkers[i].compare(dev_mac)==0){
          return true;
      }
  }
  return false;
}

void Device::addTalker(std::string dev_mac){
  if(!(dev_mac==getDeviceMAC())){
    talkers.push_back(dev_mac);
  }
}

void Device::removeTalker(std::string dev_mac){
  for(unsigned long i=0; i < talkers.size() ; i++){
    if(talkers[i].compare(dev_mac)==0){
      talkers.erase(talkers.begin()+i);
      return;
    }
  }
}

void Device::addEndPoint(std::string dev_mac){
  for(unsigned long i=0; i< end_point.size() ; i++){
    if(end_point[i].compare(dev_mac)==0){
      return;
    }
  }
  if(!(dev_mac==getDeviceMAC())){
    end_point.push_back(dev_mac);
  }
}

void Device::removeEndPoint(std::string dev_mac){
  for(unsigned long i=0; i < end_point.size() ; i++){
    if(end_point[i].compare(dev_mac)==0){
      end_point.erase(end_point.begin()+i);
      return;
    }
  }
}

void Device::addStartPoint(std::string dev_mac){
  for(unsigned long i=0; i< start_point.size() ; i++){
    if(start_point[i].compare(dev_mac)==0){
      return;
    }
  }
  if(!(dev_mac==getDeviceMAC())){
    start_point.push_back(dev_mac);
  }
}

void Device::removeStartPoint(std::string dev_mac){
  for(unsigned long i=0; i < start_point.size() ; i++){
    if(start_point[i].compare(dev_mac)==0){
      start_point.erase(start_point.begin()+i);
      return;
    }
  }
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
