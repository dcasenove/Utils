#include "Device.h"
#include <iostream>

Device::Device(std::string mac){
  isAP=false;
  mac_address=mac;
  main_device=NULL;
  power.antenna_signal=0;
  power.antenna_noise=0;
  isLocallyAdministered=checkLocalAdministered(mac_address);
  isMulticastAddress=checkMulticastMAC(mac_address);
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
      printf("\tSignal : %d\n",(signed char) power.antenna_signal);
      printf("\tNoise : %d\n",(signed char) power.antenna_noise);
      printf("\tChannel : %d\n", power.channel);
  }
  std::cout << "******************************************" << std::endl;
}

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
