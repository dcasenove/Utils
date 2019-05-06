#include "RadiotapScanner.h"
#include <time.h>
using namespace std;

std::unordered_map<std::string,Device*> devices;

/*CRC check*/
uint32_t crc32(uint32_t bytes_sz, const uint8_t *bytes){
   uint32_t crc = ~0;
   uint32_t i;
   for(i = 0; i < bytes_sz; ++i){
     crc = crctable[(crc ^ bytes[i]) & 0xff] ^ (crc >> 8);
   }
   return ~crc;
}


void RadiotapScanner::findUnicastAddress(std::string mac){
  std::string octect1 = mac.substr(0,2);
  std::stringstream ss;
  ss << std::hex << octect1;
  unsigned np;
  ss >> np;
  std::bitset<8> b(np);
  b.set(0,0);
  std::stringstream news;
  std::string newmac;

  news << std::hex << b.to_ulong();
  newmac = news.str();
  newmac.append(mac.substr(2,15));
  auto search = devices.find(mac);
  auto search2 = devices.find(newmac);
  if(search2!=devices.end()){
    search2->second->local_assigned_interfaces.push_back(search->second);
    search->second->main_device=search2->second;
  }
}

/*Find globally administered MAC address*/
void RadiotapScanner::findGloballyAdministeredInterface(std::string mac){
  auto search = devices.find(mac);
  //devices.erase(search);
  std::string last_three_octects=mac.substr(9,8);
  for(auto n : devices){
    if(n.first.compare(mac)!=0){
      std::size_t s = n.first.find(last_three_octects,9);
      if((s!=std::string::npos)){//&&(n.first.compare(mac)!=0)
        n.second->local_assigned_interfaces.push_back(search->second);
        search->second->main_device=n.second;
        return;
      }
    }
  }
  for(auto n : arp){
    if(n.compare(mac)!=0){
      std::size_t s = n.find(last_three_octects,9);
      if((s!=std::string::npos)){
        auto search2 = devices.find(n);
        if(search2==devices.end()){
          Device *d = new Device(n);
          devices.insert({n,d});
        }
        search2 = devices.find(n);
        search2->second->local_assigned_interfaces.push_back(search->second);
        search->second->main_device=search2->second;
      }
    }
  }
}

/*Find physical address of virtual devices*/
  void RadiotapScanner::findMainMACAP(std::string mac){
    vector<std::string> found;
    auto s = devices.find(mac);
    std::string first_five_octects;
    if(!s->second->isLocallyAdministered){
      first_five_octects=mac.substr(0,15);
      found.push_back(mac);
    }
    else if(s->second->isLocallyAdministered && s->second->main_device!=NULL){
      std::string mainmac = s->second->main_device->getDeviceMAC();
      first_five_octects=mainmac.substr(0,15);
      found.push_back(mainmac);
    }
    else if(s->second->isLocallyAdministered && s->second->main_device==NULL){
      std::string octect1 = mac.substr(0,2);
      std::stringstream ss;
      ss << std::hex << octect1;
      unsigned np;
      ss >> np;
      std::bitset<8> b(np);
      b.set(1,0);
      std::stringstream news;
      std::string newmac;

      news << std::hex << b.to_ulong();
      newmac = news.str();
      newmac.append(mac.substr(2,15));
      first_five_octects=newmac.substr(0,15);
      found.push_back(newmac);
    }
    for(auto n : devices){
      std::size_t s = n.first.find(first_five_octects,0);
      if((s!=std::string::npos)){
        found.push_back(n.first);
      }
    }
    for(auto n : arp){
      std::size_t s = n.find(first_five_octects,0);
      if((s!=std::string::npos)){
        auto search = devices.find(n);
        if(search==devices.end()){
          Device *d = new Device(n);
          devices.insert({n,d});
          found.push_back(n);
        }
      }
    }
    vector<unsigned> min_vector;
    for(auto str : found){
      std::string octect6 = str.substr(str.size()-2,2);
      std::stringstream ss;
      ss << std::hex << octect6;
      unsigned np;
      ss >> np;
      min_vector.push_back(np);
    }
    int min=0;
    for(unsigned long i=0; i<min_vector.size(); i++){
      if(min_vector[i]< min_vector[min]){
        min=i;
      }
    }
    auto search = devices.find(found[min]);
    if(search==devices.end()){
      auto toinclude = devices.find(mac);
      toinclude->second->main_device=toinclude->second;
      return;
    }
    auto toinclude = devices.find(mac);
    toinclude->second->main_device=search->second;
    //Controllare assegnamento successivo
    search->second->local_assigned_interfaces.push_back(toinclude->second);
  }

/*Hex string converter*/
template<typename TInputIter>
std::string make_hex_string(TInputIter first, TInputIter last,
   bool use_uppercase = true, bool insert_spaces = false){
    std::ostringstream ss;
    ss << std::hex << std::setfill('0');
    if (use_uppercase)
        ss << std::uppercase;
    while (first != last)
    {
        ss << std::setw(2) << static_cast<int>(*first++);
        if (insert_spaces && first != last)
            ss << ":";
    }
    return ss.str();
}

/*MAC address validity check */
bool isValidMAC(std::string mac_address){
    std::string multicast("01:00:5e");
    std::string broadcast("ff:ff:ff:ff:ff:ff");
    std::string ipv6multicast("33:33:00:00:00");
    std::string ipv6multicast2("33:33:ff");
    std::string cdp("01:00:0c:cc:cc:cc");
    std::string stp("01:80:c2:00:00:00");

    std::size_t found;
    found = mac_address.find(multicast);
    if(found!=std::string::npos){
      return false;
    }
    found = mac_address.find(broadcast);
    if(found!=std::string::npos){
      return false;
    }
    found = mac_address.find(ipv6multicast);
    if(found!=std::string::npos){
      return false;
    }
    found = mac_address.find(ipv6multicast2);
    if(found!=std::string::npos){
      return false;
    }
    found = mac_address.find(cdp);
    if(found!=std::string::npos){
      return false;
    }
    found = mac_address.find(stp);
    if(found!=std::string::npos){
      return false;
    }
    return true;
}

/*Convert MHz frequency to channel integer*/
int ieee80211_mhz_to_chan(unsigned int freq){
  unsigned int i;
  for(i = 0; i < NUM_FREQ_CVT; i++){
    if(freq >= freq_cvt[i].fmin && freq <= freq_cvt[i].fmax){
      return ((freq - freq_cvt[i].fmin) / FREQ_STEP) + freq_cvt[i].cmin;
    }
  }
  return -1;
}

static void print_radiotap_namespace(struct ieee80211_radiotap_iterator *iter,
  struct signal_power *power){

	switch (iter->this_arg_index) {
	case IEEE80211_RADIOTAP_TSFT:
		break;
	case IEEE80211_RADIOTAP_FLAGS:
		break;
	case IEEE80211_RADIOTAP_RATE:
		break;
	case IEEE80211_RADIOTAP_CHANNEL:
    power->channel=ieee80211_mhz_to_chan(le16toh(*(unsigned int *) iter->this_arg));
    break;
	case IEEE80211_RADIOTAP_FHSS:
	case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
    power->antenna_signal=*iter->this_arg;
    break;
	case IEEE80211_RADIOTAP_DBM_ANTNOISE:
    power->antenna_noise=*iter->this_arg;
    break;
	case IEEE80211_RADIOTAP_LOCK_QUALITY:
	case IEEE80211_RADIOTAP_TX_ATTENUATION:
	case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
	case IEEE80211_RADIOTAP_DBM_TX_POWER:
	case IEEE80211_RADIOTAP_ANTENNA:
    break;
	case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
    break;
	case IEEE80211_RADIOTAP_DB_ANTNOISE:
    break;
	case IEEE80211_RADIOTAP_TX_FLAGS:
		break;
	case IEEE80211_RADIOTAP_RX_FLAGS:
		break;
	case IEEE80211_RADIOTAP_RTS_RETRIES:
	case IEEE80211_RADIOTAP_DATA_RETRIES:
		break;
	default:
		printf("\tBOGUS DATA\n");
		break;
	}
}

void dissectpacket(SUPPRESS_NOT_USED_WARN u_char *args, const struct pcap_pkthdr *header,const u_char *packet){
    struct ieee80211_radiotap_iterator iter;
    struct signal_power power;
    static int count = 1;
    count++;
    int err;
    err=ieee80211_radiotap_iterator_init(&iter, (ieee80211_radiotap_header*)packet, header->len,/* &vns*/ NULL);
    if(err){
        return;
    }
    	while (!(err = ieee80211_radiotap_iterator_next(&iter))) {
		if (iter.this_arg_index == IEEE80211_RADIOTAP_VENDOR_NAMESPACE) {
		} else if (iter.is_radiotap_ns)
			print_radiotap_namespace(&iter,&power);
	  }
	if (err != -ENOENT) {
		//printf("Radiotap malformato\n");
		return ;
	}
    time(&power.timestamp);
    struct ieee80211_radiotap_header *radiotapheader;
    radiotapheader = (ieee80211_radiotap_header*) packet;
    uint32_t crc = crc32(header->len-4-radiotapheader->it_len,packet+radiotapheader->it_len);
    uint32_t received_crc;
    memcpy(&received_crc,&packet[header->len-4],4);
    if(crc!=received_crc){
      return;
    }

    struct ieee80211mac *frame80211;
    struct framectl_bits *ctl;

    frame80211 = (ieee80211mac *) (packet+radiotapheader->it_len);
    ctl = (framectl_bits *)&frame80211->framectl;
    switch(ctl->type){
      //Management Frame
      case 0:
        switch(ctl->subtype){
          //Beacon frame
          case 8:{
            struct beacon_frame *bframe;
            bframe = (beacon_frame *)(packet+radiotapheader->it_len);
            bframe->ssid[bframe->length]='\0';
            auto transmitter_mac = make_hex_string(std::begin(bframe->transmitter), std::end(bframe->transmitter), false,  true);
            auto search = devices.find(transmitter_mac);
            if(search!=devices.end()){
              search->second->setAP(std::string(bframe->ssid));
              search->second->addPowerValues(power);
            }
            else{
              Device* d = new Device(transmitter_mac);
              d->setAP(std::string(bframe->ssid));
              d->addPowerValues(power);
              devices.insert({transmitter_mac,d});
            }
            return;
          }
          //Probe request
          case 4:{
            struct disassociation_frame *frame;
            frame = (disassociation_frame *)(packet+radiotapheader->it_len);
            auto transmitter_mac = make_hex_string(std::begin(frame->transmitter), std::end(frame->transmitter), false,  true);
            auto search = devices.find(transmitter_mac);
            if(search == devices.end()){
              Device * d = new Device(transmitter_mac);
              d->addPowerValues(power);
              devices.insert({transmitter_mac,d});
            }
            return;
          }
          //Association response
          case 1:{
            struct association_frame *frame;
            frame = (association_frame *)(packet+radiotapheader->it_len);
            if(frame->response == 0){
              auto transmitter_mac = make_hex_string(std::begin(frame->transmitter), std::end(frame->transmitter), false,  true);
              auto search = devices.find(transmitter_mac);
              if(search == devices.end()){
                Device * d = new Device(transmitter_mac);
                d->addPowerValues(power);
                devices.insert({transmitter_mac,d});
              }
              auto receiver_mac = make_hex_string(std::begin(frame->receiver), std::end(frame->receiver), false, true);
              auto search2 = devices.find(receiver_mac);
              if(search2==devices.end()){
                Device* d = new Device(receiver_mac);
                devices.insert({receiver_mac,d});
              }
              search = devices.find(transmitter_mac);
              search2 = devices.find(receiver_mac);
              if(!search->second->isTalking(receiver_mac)){
                search->second->addTalker(receiver_mac);
                search2 = devices.find(receiver_mac);
                search2->second->addTalker(transmitter_mac);
              }
            }
            return;
          }
          //Deassociation
          case 10:{
            struct disassociation_frame *frame;
            frame = (disassociation_frame *)(packet+radiotapheader->it_len);
            auto destination_mac = make_hex_string(std::begin(frame->destination), std::end(frame->destination), false, true);
            auto transmitter_mac = make_hex_string(std::begin(frame->transmitter), std::end(frame->transmitter), false,  true);
            auto search = devices.find(transmitter_mac);
            if(search == devices.end()){
              return;
            }
            auto search2 = devices.find(destination_mac);
            if(search2 == devices.end()){
              return;
            }
            search = devices.find(transmitter_mac);
            search2 = devices.find(destination_mac);
            if(search->second->isTalking(destination_mac)){
              search->second->removeTalker(destination_mac);
              search->second->removeEndPoint(destination_mac);
              search->second->removeStartPoint(destination_mac);
              search2->second->removeTalker(transmitter_mac);
            }
            return;
          }
          //Deauth
          case 12:{
            //Riutilizzo control frame
            struct control_frames *frame;
            frame = (control_frames *) (packet + radiotapheader->it_len);
            auto receiver_mac= make_hex_string(std::begin(frame->receiver), std::end(frame->receiver), false,  true);
            auto transmitter_mac = make_hex_string(std::begin(frame->transmitter), std::end(frame->transmitter), false,  true);
            //Potrei aggiungerli comunque ai devices se non presenti e non metterli come talkers
            auto search = devices.find(transmitter_mac);
            if(search == devices.end()){
              return;
            }
            auto search2 = devices.find(receiver_mac);
            if(search2 == devices.end()){
              return;
            }
            search = devices.find(transmitter_mac);
            search2 = devices.find(receiver_mac);
            if(search->second->isTalking(receiver_mac)){
              search->second->removeTalker(receiver_mac);
              search->second->removeEndPoint(receiver_mac);
              search->second->removeStartPoint(receiver_mac);
              search2->second->removeEndPoint(transmitter_mac);
              search2->second->removeStartPoint(transmitter_mac);
              search2->second->removeTalker(transmitter_mac);
            }
            return;
          }
          //Default
          default:
            return;
        }
      //Control Frame
      case 1:
        switch(ctl->subtype){
          //Block ack req
          case 8:
          //Block ack
          case 9:
          //RTS
          case 11:{
            struct control_frames *frame;
            frame = (control_frames *)(packet+radiotapheader->it_len);

            auto transmitter_mac = make_hex_string(std::begin(frame->transmitter), std::end(frame->transmitter), false,  true);
            auto search = devices.find(transmitter_mac);
            if(search == devices.end()){
                if(isValidMAC(transmitter_mac)){
                    Device *d = new Device(transmitter_mac);
                    d->addPowerValues(power);
                    devices.insert({transmitter_mac,d});
                }
            }
            auto receiver_mac = make_hex_string(std::begin(frame->receiver), std::end(frame->receiver), false,  true);
            auto search2= devices.find(receiver_mac);
            if(search2 == devices.end()){
                if(isValidMAC(receiver_mac)){
                    Device *d = new Device(receiver_mac);
                  //  d->addPowerValues(power);
                    devices.insert({receiver_mac,d});
                }
            }
            if(transmitter_mac.compare(receiver_mac)!=0){
              search = devices.find(transmitter_mac);
              search2 = devices.find(receiver_mac);
              if(search!=devices.end() && search2!=devices.end()){
                if(!search2->second->isTalking(transmitter_mac)){
                  search->second->addTalker(receiver_mac);
                  search->second->addPowerValues(power);
                  search2->second->addTalker(transmitter_mac);
                  search2->second->addPowerValues(power);
                }
              }
            }
          }
            return;
          default:
            return;
        }
      //Data frame
      //Controlli To DS, From DS per capire entry/exit point
      //Togliere entrypoint/exitpoint su deautenticazione e disassociazione
      case 2:
        switch(ctl->subtype){
          //Data
          case 0:
          //Null no data
          case 4:
          //QoS data
          case 8:
          //QoS null no data
          case 12:{
            struct data_frames *frame;
            frame = (data_frames *)(packet+radiotapheader->it_len);
            //Wireless distribution system
            if(ctl->to_ds==1 && ctl->from_ds==1){
              return;
            }
            //Address 1 = Destination
            //Address 2 = BSSID
            //Address 3 = Source
            //Entra su wifi
            //Da cavo a wifi
            //Controllare valori power wifi, probabilmente va su transmitter
            if(ctl->to_ds==0 && ctl->from_ds==1){
              auto transmitter_mac = make_hex_string(std::begin(frame->address2), std::end(frame->address2), false, true);
              auto search = devices.find(transmitter_mac);
              if(search == devices.end()){
                if(isValidMAC(transmitter_mac)){
                  Device *d = new Device(transmitter_mac);
                  d->addPowerValues(power);
                  devices.insert({transmitter_mac,d});
                }
              }
              auto receiver_mac = make_hex_string(std::begin(frame->address1), std::end(frame->address1), false, true);
              auto search2 = devices.find(receiver_mac);
              if(search2 == devices.end()){
                if(isValidMAC(receiver_mac)){
                  Device *d = new Device(receiver_mac);
                //  d->addPowerValues(power);
                  devices.insert({receiver_mac,d});
                }
              }
              auto source_mac = make_hex_string(std::begin(frame->address3), std::end(frame->address3), false, true);
              auto search3 = devices.find(source_mac);
              if(search3 == devices.end()){
                if(isValidMAC(source_mac)){
                  Device *d =new Device(source_mac);
                  d->addPowerValues(power);
                  devices.insert({source_mac,d});
                }
              }
              search = devices.find(transmitter_mac);
              search2 = devices.find(receiver_mac);
              search3 = devices.find(source_mac);
              if(search!=devices.end() && search2!=devices.end()){
                search->second->addEndPoint(receiver_mac);
                if((!search2->second->isTalking(transmitter_mac))&&(transmitter_mac.compare(receiver_mac)!=0)){
                  search->second->addTalker(receiver_mac);
                  search->second->addEndPoint(receiver_mac);
                  search2->second->addTalker(transmitter_mac);
                //  search->second->addPowerValues(power);
                }
              }


                //search3->second->addPowerValues(power);
               if(search!=devices.end() && search3!=devices.end()){
                 search->second->addPowerValues(power);
                 search->second->addStartPoint(source_mac);
                if((!search3->second->isTalking(transmitter_mac))&&(transmitter_mac.compare(source_mac)!=0)){
                  search->second->addTalker(source_mac);
                //  search->second->addPowerValues(power);
                  search3->second->addPowerValues(power);
                  search->second->addStartPoint(source_mac);
                  search3->second->addTalker(transmitter_mac);
                }
              }
            }

            //Address 1 = BSSID
            //Address 2 = Source
            //Address 3 = Destination
            //Esce da wifi
            //Da wifi a cavo  Power = Source
            if(ctl->to_ds==1 && ctl->from_ds==0){
              auto transmitter_mac = make_hex_string(std::begin(frame->address1), std::end(frame->address1), false, true);
              auto search = devices.find(transmitter_mac);
              if(search == devices.end()){
                if(isValidMAC(transmitter_mac)){
                  Device *d = new Device(transmitter_mac);
                //  d->addPowerValues(power);
                  devices.insert({transmitter_mac,d});
                }
              }
              auto receiver_mac = make_hex_string(std::begin(frame->address3), std::end(frame->address3), false, true);
              auto search2 = devices.find(receiver_mac);
              if(search2 == devices.end()){
                if(isValidMAC(receiver_mac)){
                  Device *d = new Device(receiver_mac);
                //  d->addPowerValues(power);
                  devices.insert({receiver_mac,d});
                }
              }
              auto source_mac = make_hex_string(std::begin(frame->address2), std::end(frame->address2), false, true);
              auto search3 = devices.find(source_mac);
              if(search3 == devices.end()){
                if(isValidMAC(source_mac)){
                  Device *d =new Device(source_mac);
                  d->addPowerValues(power);
                  devices.insert({source_mac,d});
                }
              }
              search = devices.find(transmitter_mac);
              search2 = devices.find(receiver_mac);
              search3 = devices.find(source_mac);
              if(search!=devices.end() && search2!=devices.end()){
                search->second->addStartPoint(receiver_mac);
                if((!search2->second->isTalking(transmitter_mac))&&(transmitter_mac.compare(receiver_mac)!=0)){
                  search->second->addTalker(receiver_mac);
                  search->second->addStartPoint(receiver_mac);
                  search2->second->addTalker(transmitter_mac);
                  //search2->second->addPowerValues(power);
                }
              }
                //Mettere i add power values fuori dall'if
                if(search!=devices.end() && search3!=devices.end()){
                search3->second->addPowerValues(power);
                search->second->addEndPoint(source_mac);
                if((!search3->second->isTalking(transmitter_mac))&&(transmitter_mac.compare(source_mac)!=0)){
                  search->second->addTalker(source_mac);
                  search->second->addEndPoint(source_mac);
                  search3->second->addPowerValues(power);
                  search3->second->addTalker(transmitter_mac);
                  //search3->second->addPowerValues(power);

                }
              }
            }
            return;
          }
          default:
            return;
        }
      //No 0-1-2 type frames
      default:
        return;
    }
}

RadiotapScanner::RadiotapScanner(std::vector<std::string> arp_results){
  //Lookup device
  radiotap_scanner=this;
  arp=arp_results;
  live_status=true;
  //Errori valgrind dovuti a pcap_lookupdev
  device = pcap_lookupdev(errbuf);
  if(device == NULL){
      throw std::invalid_argument("Device di rete non trovato\n");
  }
  //Aggiungere input vettore mac e controllo
  cout << ("Device scelto : ") << device << endl;
  //Get Netmask
  if(pcap_lookupnet(device, &network, &mask, errbuf) == -1) {
   cout << ("Errore netmask del device") << device << endl;
   network = 0;
   mask = 0;
  }
  //Create and set up device
  handle = pcap_create(device, errbuf);
  if(handle==NULL){
    throw std::invalid_argument("Errore creazione handle");
  }
  //Monitor mode
  if(pcap_set_rfmon(handle, 1)!=0){
    pcap_close(handle);
    throw std::invalid_argument("Errore set monitor mode");
  }
  //Promiscous mode
  if(pcap_set_promisc(handle, 1)!=0){
    pcap_set_rfmon(handle, 0);
    pcap_close(handle);
    throw std::invalid_argument("Errore set promiscous mode");
  }
  //Snaplen
  if(pcap_set_snaplen(handle, 2048)!=0){
    pcap_set_rfmon(handle, 0);
    pcap_set_promisc(handle, 0);
    pcap_close(handle);
    throw std::invalid_argument("Errore set snaplen");
  }
  //Timeout
  if(pcap_set_timeout(handle, 1000)!=0){
    pcap_set_rfmon(handle, 0);
    pcap_set_promisc(handle, 0);
    pcap_close(handle);
    throw std::invalid_argument("Errore set timeout");
  }
  //Warnings activate
  if(pcap_activate(handle)!=0){
    pcap_set_rfmon(handle, 0);
    pcap_set_promisc(handle, 0);
    pcap_close(handle);
    throw std::invalid_argument("Errore attivazione handle");
  }
  //Compile filter
  if(pcap_compile(handle,&fp,filter,0,network) == PCAP_ERROR){
    pcap_set_rfmon(handle, 0);
    pcap_set_promisc(handle, 0);
    pcap_close(handle);
    throw std::invalid_argument("Errore compile filtro");
    //  return 1;
  }
  //Set filter
  if(pcap_setfilter(handle,&fp) == -1){
    pcap_set_rfmon(handle, 0);
    pcap_set_promisc(handle, 0);
    pcap_close(handle);
    throw std::invalid_argument("Errore set filtro");
    //  return 1;
  }
}

RadiotapScanner::RadiotapScanner(char *arg, std::vector<std::string> arp_results){
  string file;
  file=arg;
  pcap_t * pcap = pcap_open_offline(file.c_str(), errbuf);
  struct pcap_pkthdr *header;
  const u_char *data;
  live_status=false;
  arp=arp_results;
  u_int packetCount = 0;
  int returnValue;
    while ((returnValue = pcap_next_ex(pcap, &header, &data) >= 0) /*&& (packetCount<10)*/){
      // Show the packet number
      dissectpacket(NULL,header,data);
    }
  packResults();
  pcap_close(pcap);
}

void RadiotapScanner::packResults(){
  std::vector<Device *> ap;
  for( const auto& n : devices ) {
    if(n.second->isAP){
      ap.push_back(n.second);
    }
  }
  for(const auto n : ap){
    std::string mac = n->getDeviceMAC();
    checkLocalAdministered(mac);
/*
    for(auto v : n->talkers){
      //std::cout << v.getDeviceMAC() << " " << v.getDeviceSSID() << std::endl;
      std::string mac = v;
      checkLocalAdministered(mac);
  }*/
}

  for(const auto i : devices){
    if(i.second->isLocallyAdministered){
      findGloballyAdministeredInterface(i.second->mac_address);
    }
  }

/*
  for( const auto n : ap ){
    findMainMACAP(n->getDeviceMAC());
  }*/

  for(const auto n : devices){
    findMainMACAP(n.second->getDeviceMAC());
  }

  for(const auto i : devices){
    if(i.second->isMulticastAddress){
      findUnicastAddress(i.second->mac_address);
    }
  }
  //Spostato da sopra
/*
  for(const auto i : devices){
      if(i.second->isLocallyAdministered){
        findGloballyAdministeredInterface(i.second->mac_address);
    }
  }

  for( const auto n : devices ){
    findMainMACAP(n.second->getDeviceMAC());
  }*/

}

void RadiotapScanner::startScan(int time){
  alarm(time);
  signal(SIGALRM, RadiotapScanner::alarmHandler);
  pcap_loop(handle,0,dissectpacket,NULL);
}

void RadiotapScanner::alarmHandler(SUPPRESS_NOT_USED_WARN int sig){
  radiotap_scanner->stop_pack();
}

void RadiotapScanner::stop_pack(){
  pcap_breakloop(handle);
  packResults();
}
void RadiotapScanner::close(){
  if(live_status){
    pcap_set_rfmon(handle,0);
    pcap_set_promisc(handle,0);
    pcap_freecode(&fp);
    pcap_close(handle);
  }
  for(const auto n : devices){
    delete(n.second);
  }
}

void RadiotapScanner::feedARPResults(vector<std::string> arp_r){
  arp=arp_r;
}

std::unordered_map<std::string,Device*> RadiotapScanner::getResult(){
  return devices;
}

WiFiResult* RadiotapScanner::getWiFiResult(){
  std::list<device_wifi> device_list;
  for(const auto n : devices){
    //Utilizzare MAC principale e non dell'AP
    if(n.second->isAP){
      device_wifi d;
      if(n.second->main_device!=NULL){
        d.mac_wifidevice = n.second->main_device->getDeviceMAC();
      }
      else{
        d.mac_wifidevice = n.second->getDeviceMAC();
      }
      d.ssid = n.second->getDeviceSSID();
      d.antenna_signal=n.second->power.antenna_signal;
      d.antenna_noise=n.second->power.antenna_noise;
      d.channel=n.second->power.channel;
      for(auto i : n.second->end_point){
        auto search = devices.find(i);
        auto k = search->second->getDeviceMAC();
        std::cout << k << " " ;
        if(search->second->main_device!=NULL){
          k = search->second->main_device->getDeviceMAC();
        }
        if(k==d.mac_wifidevice){
          continue;
        }
        bool found=false;
        std::list<connected_device>::iterator connected_iterator;
        for(connected_iterator = d.connected.begin();connected_iterator!=d.connected.end();connected_iterator++){
          if(connected_iterator->mac_pc==k){
            found=true;
          }
        }
        if(!found){
          struct connected_device c;
          c.mac_pc=k;
          c.isDirectlyConnected=false;
          d.connected.push_back(c);
        }
      }
      for(auto i : n.second->start_point){
        auto search = devices.find(i);
        auto k = search->second->getDeviceMAC();
        if(search->second->isAP){
          continue;
        }
        if(search->second->main_device!=NULL){
          k = search->second->main_device->getDeviceMAC();
          if(search->second->main_device->isAP){
            continue;
          }
          //Controllo che l'entry point non sia un AP
          bool found=false;
          for(const auto locald : search->second->main_device->local_assigned_interfaces){
            if(locald->isAP){
              found=true;
            }
          }
          if(found){
            continue;
          }
        }
        if(k==d.mac_wifidevice){
          continue;
        }
        bool found=false;
        std::list<connected_device>::iterator connected_iterator;
        for(connected_iterator = d.connected.begin();connected_iterator!=d.connected.end();connected_iterator++){
          if(connected_iterator->mac_pc==k){
            found=true;
          }
        }
        if(!found){
          struct connected_device c;
          c.mac_pc=k;
          c.isDirectlyConnected=false;
          d.connected.push_back(c);
        }
      }
      device_list.push_back(d);
    }
  }
  //Unire cicli
  std::list<pc_wifi> pc_list;
  for(const auto n : devices){
    if(!n.second->isAP){
      bool main_ap=false;
      for(auto i : n.second->local_assigned_interfaces){
        if(i->isAP){
          main_ap=true;
          break;
        }
      }
      if(main_ap){
        continue;
      }
      pc_wifi pc;
      std::string ssid_connected;
      if(n.second->main_device!=NULL){
        bool main_ap=false;
        std::list<device_wifi>::iterator it1;
        for(it1 = device_list.begin() ; it1 != device_list.end() ; it1++){
          if(n.second->main_device->mac_address==it1->mac_wifidevice){
            main_ap=true;
          }
        }
        if(main_ap){
          continue;
        }
        if(!n.second->main_device->isAP){
          pc.mac_pc = n.second->main_device->getDeviceMAC();
          pc.antenna_signal=n.second->main_device->power.antenna_signal;
          pc.antenna_noise=n.second->main_device->power.antenna_noise;
        }
        else{
          continue;
        }
      }
      else{
        pc.mac_pc = n.second->getDeviceMAC();
        pc.antenna_signal=n.second->power.antenna_signal;
        pc.antenna_noise=n.second->power.antenna_noise;
      }
      if(n.second->talkers.size()!=0){
        pc.mac_wifidevice=n.second->talkers[0];
        auto search = devices.find(n.second->talkers[0]);
        ssid_connected=search->second->getDeviceSSID();
        if(search->second->main_device!=NULL){
          pc.mac_wifidevice=search->second->main_device->getDeviceMAC();
        }
      }
      std::list<pc_wifi>::iterator it;
      bool found=false;
      for( it = pc_list.begin() ; it != pc_list.end() ; it++){
        if(pc.mac_pc==it->mac_pc){
          found=true;
        }
      }
      if(!found){
        std::list<device_wifi>::iterator device_list_it;
        for(device_list_it = device_list.begin(); device_list_it!=device_list.end();device_list_it++){
          if(device_list_it->mac_wifidevice==pc.mac_wifidevice && device_list_it->ssid==ssid_connected){
            std::list<connected_device>::iterator connected_iterator;
            bool found=false;
            for(connected_iterator=device_list_it->connected.begin();connected_iterator!=device_list_it->connected.end();connected_iterator++){
              if(connected_iterator->mac_pc==pc.mac_pc){
                found=true;
                connected_iterator->isDirectlyConnected=true;
              }
            }
            if(!found){
              struct connected_device c;
              c.mac_pc=pc.mac_pc;
              c.isDirectlyConnected=true;
              device_list_it->connected.push_back(c);
            }
          }
        }
        pc_list.push_back(pc);
      }
    }
  }
  WiFiResult *toreturn = new WiFiResult(device_list,pc_list);
  return toreturn;
}
