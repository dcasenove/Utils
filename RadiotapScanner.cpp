#include "RadiotapScanner.h"
#include <time.h>
using namespace std;

std::unordered_map<std::string,Device*> devices;

uint32_t crc32(uint32_t bytes_sz, const uint8_t *bytes){
   uint32_t crc = ~0;
   uint32_t i;
   for(i = 0; i < bytes_sz; ++i){
     crc = crctable[(crc ^ bytes[i]) & 0xff] ^ (crc >> 8);
   }
   return ~crc;
}

void RadiotapScanner::findGloballyAdministeredInterface(std::string mac){
  std::cout << "Dentro find di " << mac << std::endl;
  auto search = devices.find(mac);
  //devices.erase(search);
  std::string last_three_octects=mac.substr(9,8);
  for(auto n : devices){
    std::cout << "Dentro for find" << std::endl;
    if(n.first.compare(mac)!=0){
      std::cout << "ultimi 3 ottetti" << last_three_octects << std::endl;
      std::size_t s = n.first.find(last_three_octects,9);
      if((s!=std::string::npos)){//&&(n.first.compare(mac)!=0)
        std::cout << "Dentro if" <<  mac << std::endl;
        n.second->local_assigned_interfaces.push_back(search->second);
        search->second->main_device=n.second;
        std::cout << " Main device " << n.second->getDeviceMAC() << std::endl;
        return;
      }
    }
  }
  for(auto n : arp){
    std::cout << "Cerco nei risultati arp scan" << std::endl;
    if(n.compare(mac)!=0){
      std::cout << "ultimi 3 ottetti" << last_three_octects << std::endl;
      std::size_t s = n.find(last_three_octects,9);
      if((s!=std::string::npos)){
        std::cout << "Dentro if controllo arp" << std::endl;
        auto search2 = devices.find(n);
        if(search2==devices.end()){
          Device *d = new Device(n);
          devices.insert({n,d});
        }
        std::cout << "Dopo if creazione" << std::endl;
        search2 = devices.find(n);
        search2->second->local_assigned_interfaces.push_back(search->second);
        search->second->main_device=search2->second;
      }
    }
  }
  //Risultati arp scan
}

  void RadiotapScanner::findMainMACAP(std::string mac){
    std::string first_five_octects=mac.substr(0,15);
    std::cout << "Primi cinque ottetti" << first_five_octects << std::endl;
    vector<std::string> found;
    found.push_back(mac);
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
      std::cout << "Stringa : " <<  "size : " << str.size() << std::endl;
      std::string octect6 = str.substr(str.size()-2,2);
      std::cout << "Ultimo ottetto : " << octect6 << std::endl;
      std::stringstream ss;
      ss << std::hex << octect6;
      unsigned np;
      ss >> np;
      std::cout << "NP:" << np << std::endl;
      min_vector.push_back(np);
    }
    int min=0;
    for(unsigned long i=0; i<min_vector.size(); i++){
      if(min_vector[i]< min_vector[min]){
        min=i;
      }
    }
    auto search = devices.find(found[min]);
    std::cout << "Mac : " << search->first << std::endl;
    auto toinclude = devices.find(mac);
    toinclude->second->main_device=search->second;
    //Controllare assegnamento successivo
    search->second->local_assigned_interfaces.push_back(toinclude->second);
  }



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

void dissectpacket(u_char *args, const struct pcap_pkthdr *header,const u_char *packet){
    struct ieee80211_radiotap_iterator iter;
    struct signal_power power;
    static int count = 1;
    int i;
    cout << ("Pacchetto : ") << count << endl;
    printf("%ld.%06d\n", header->ts.tv_sec, header->ts.tv_usec);
    cout << ("Lunghezza header : ") << (int)header->len << endl;
    count++;
    int err;
    err=ieee80211_radiotap_iterator_init(&iter, (ieee80211_radiotap_header*)packet, header->len,/* &vns*/ NULL);
    if(err){
        cout << ("Malformed header") << endl;
        return;
    }
    cout << ("Init valido") << endl;
    printf("===RADIOTAP HEADER===\n");
    	while (!(err = ieee80211_radiotap_iterator_next(&iter))) {
		if (iter.this_arg_index == IEEE80211_RADIOTAP_VENDOR_NAMESPACE) {
	/*		printf("\tvendor NS (%.2x-%.2x-%.2x:%d, %d bytes)\n",
				iter.this_arg[0], iter.this_arg[1],
				iter.this_arg[2], iter.this_arg[3],
				iter.this_arg_size - 6);
			for (i = 6; i < iter.this_arg_size; i++) {
				if (i % 8 == 6)
					printf("\t\t");
				else
					printf(" ");
				printf("%.2x", iter.this_arg[i]);
			}
			printf("\n");*/
		} else if (iter.is_radiotap_ns)
			print_radiotap_namespace(&iter,&power);
      //		else if (iter.current_namespace == &vns_array[0])
//			print_test_namespace(&iter);
	}
	if (err != -ENOENT) {
		printf("Radiotap malformato\n");
		return ;
	}
    time(&power.timestamp);
    struct ieee80211_radiotap_header *radiotapheader;
    radiotapheader = (ieee80211_radiotap_header*) packet;
    printf("Radiotap header len %u\n", radiotapheader->it_len);

    //Aggiunto controllo CRC
    uint32_t crc = crc32(header->len-4-radiotapheader->it_len,packet+radiotapheader->it_len);
    uint32_t received_crc;
    memcpy(&received_crc,&packet[header->len-4],4);
    if(crc!=received_crc){
      printf("0x%x\n", crc);
      printf("0x%x\n", received_crc);
      printf("ERRORE\n");
      return;
    }

    struct ieee80211mac *frame80211;
    struct framectl_bits *ctl;

    frame80211 = (ieee80211mac *) (packet+radiotapheader->it_len);
    ctl = (framectl_bits *)&frame80211->framectl;
    printf("\tProtocol version : %u\n", ctl->protocol_version);
    printf("\tType : %u\n", ctl->type);
    printf("\tSubtype : %u\n", ctl->subtype);
    printf("\tDuration :%u\n", frame80211->duration);
    printf("===802.11===\n");
    switch(ctl->type){
      //Management Frame
      case 0:
        switch(ctl->subtype){
          //Beacon frame
          case 8:{
            struct beacon_frame *bframe;
            bframe = (beacon_frame *)(packet+radiotapheader->it_len);
            printf("Beacon\n");
            printf("\tReceiver : ");
            printf("%02x:%02x:%02x:%02x:%02x:%02x\n", bframe->receiver[0],bframe->receiver[1],
                  bframe->receiver[2],bframe->receiver[3],bframe->receiver[4],
                  bframe->receiver[5]);
            printf("\tTransmitter : ");
            printf("%02x:%02x:%02x:%02x:%02x:%02x\n", bframe->transmitter[0],bframe->transmitter[1],
                  bframe->transmitter[2],bframe->transmitter[3],bframe->transmitter[4],
                  bframe->transmitter[5]);
            printf("\tDestination : ");
            printf("%02x:%02x:%02x:%02x:%02x:%02x\n", bframe->destination[0],bframe->destination[1],
                  bframe->destination[2],bframe->destination[3],bframe->destination[4],
                  bframe->destination[5]);
            printf("\tSeq control : %u\n", bframe->seq_control);
            printf("\tTimestamp : %llu\n", bframe->timestamp);
            printf("\tBeacon Interval : %u TU\n", bframe->beacon_interval);
            printf("\tCapability info : %u\n", bframe->capability_info);
            printf("\tTag number : %u\n", bframe->tag);
            printf("\tSSID Length : %u\n", bframe->length);
            bframe->ssid[bframe->length]='\0';
            printf("\tSSID = %s\n", bframe->ssid);
            auto transmitter_mac = make_hex_string(std::begin(bframe->transmitter), std::end(bframe->transmitter), false,  true);
            std::cout << "Il risultato della funzione e' : " << transmitter_mac << endl;
            auto search = devices.find(transmitter_mac);
            if(search!=devices.end()){
              std::cout << "Trovato,setto beacon";
              search->second->setAP(std::string(bframe->ssid));
              search->second->addPowerValues(power);
            }
            else{
              std::cout << "Non trovato, aggiungo beacon";
              Device* d = new Device(transmitter_mac);
              d->setAP(std::string(bframe->ssid));
              d->addPowerValues(power);
              devices.insert({transmitter_mac,d});
            }
            return;
          }
          //Association response
          case 1:{
            printf("Association Response\n");
            struct association_frame *frame;
            frame = (association_frame *)(packet+radiotapheader->it_len);
            if(frame->response == 0){
              printf("Associazione corretta\n");
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
            printf("Disassociazione\n");
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
              printf("Erano connessi, disassocio");
              search->second->removeTalker(destination_mac);
              search->second->removeEndPoint(destination_mac);
              search->second->removeStartPoint(destination_mac);
              search2->second->removeTalker(transmitter_mac);
            }
            return;
          }
          //Deauth
          case 12:{
            printf("Deautenticazione\n");
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
              printf("Erano connessi, deautenticazione");
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
            std::cout << "Cerco";
            if(search == devices.end()){
                std::cout << "Non trovato,aggiungo" << std::endl;
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
            //Controllare valori power wifi
            if(ctl->to_ds==0 && ctl->from_ds==1){
              auto transmitter_mac = make_hex_string(std::begin(frame->address2), std::end(frame->address2), false, true);
              auto search = devices.find(transmitter_mac);
              if(search == devices.end()){
                if(isValidMAC(transmitter_mac)){
                  Device *d = new Device(transmitter_mac);
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
                //  d->addPowerValues(power);
                  devices.insert({source_mac,d});
                }
              }
              search = devices.find(transmitter_mac);
              search2 = devices.find(receiver_mac);
              search3 = devices.find(source_mac);
              if(search!=devices.end() && search2!=devices.end() && search3!=devices.end()){
                if((!search2->second->isTalking(transmitter_mac))&&(transmitter_mac.compare(receiver_mac)!=0)){
                  search->second->addTalker(receiver_mac);
                  search->second->addEndPoint(receiver_mac);
                  search2->second->addTalker(transmitter_mac);
                //  search2->second->addPowerValues(power);
                }
                if((!search3->second->isTalking(transmitter_mac))&&(transmitter_mac.compare(source_mac)!=0)){
                  search->second->addTalker(source_mac);
                  search->second->addPowerValues(power);
                  search->second->addStartPoint(source_mac);
                  search3->second->addTalker(transmitter_mac);
                }
              }
            }

            //Address 1 = BSSID
            //Address 2 = Source
            //Address 3 = Destination
            //Esce da wifi
            //Da wifi a cavo
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
              if(search!=devices.end() && search2!=devices.end() && search3!=devices.end()){
                if((!search2->second->isTalking(transmitter_mac))&&(transmitter_mac.compare(receiver_mac)!=0)){
                  search->second->addTalker(receiver_mac);
                  search->second->addStartPoint(receiver_mac);
                  search2->second->addTalker(transmitter_mac);
                  //search2->second->addPowerValues(power);
                }
                if((!search3->second->isTalking(transmitter_mac))&&(transmitter_mac.compare(source_mac)!=0)){
                  search->second->addTalker(source_mac);
                  search->second->addEndPoint(source_mac);
                  search3->second->addPowerValues(power);
                  search3->second->addTalker(transmitter_mac);
                  //search3->second->addPowerValues(power);

                }
              }
            }
            /*
            printf("\tReceiver : ");
            printf("%02x:%02x:%02x:%02x:%02x:%02x\n", frame->receiver[0],frame->receiver[1],
                       frame->receiver[2],frame->receiver[3],frame->receiver[4],
                       frame->receiver[5]);
            printf("\tTransmitter : ");
            printf("%02x:%02x:%02x:%02x:%02x:%02x\n", frame->transmitter[0],frame->transmitter[1],
                       frame->transmitter[2],frame->transmitter[3],frame->transmitter[4],
                       frame->transmitter[5]);
            printf("\tDestination : ");
            printf("%02x:%02x:%02x:%02x:%02x:%02x\n", frame->destination[0],frame->destination[1],
                       frame->destination[2],frame->destination[3],frame->destination[4],
                       frame->destination[5]);
            auto transmitter_mac = make_hex_string(std::begin(frame->transmitter), std::end(frame->transmitter), false,  true);
            auto search = devices.find(transmitter_mac);
            std::cout << "Cerco";
            if(search == devices.end()){
               std::cout << "Non trovato,aggiungo" << std::endl;
               if(isValidMAC(transmitter_mac)){
                  Device *d = new Device(transmitter_mac);
                  devices.insert({transmitter_mac,d});
               }
            }
            auto receiver_mac = make_hex_string(std::begin(frame->receiver), std::end(frame->receiver), false,  true);
            auto search2 = devices.find(receiver_mac);
            if(search2 == devices.end()){
              if(isValidMAC(receiver_mac)){
                Device *d = new Device(receiver_mac);
                d->addPowerValues(power);
                devices.insert({receiver_mac,d});
              }
            }
            auto destination_mac = make_hex_string(std::begin(frame->destination), std::end(frame->destination), false, true);
            auto search3 = devices.find(destination_mac);
            if(search3 == devices.end()){
              if(isValidMAC(destination_mac)){
                Device *d =new Device(destination_mac);
                devices.insert({destination_mac,d});
              }
            }
           search = devices.find(transmitter_mac);
           search2 = devices.find(receiver_mac);
           search3 = devices.find(destination_mac);
           if(search!=devices.end() && search2!=devices.end() && search3!=devices.end()){
             if((!search2->second->isTalking(transmitter_mac))&&(transmitter_mac.compare(receiver_mac)!=0)){
               search->second->addTalker(receiver_mac);
               search2->second->addTalker(transmitter_mac);
               search2->second->addPowerValues(power);
             }
             if((!search3->second->isTalking(transmitter_mac))&&(transmitter_mac.compare(destination_mac)!=0)){
               search->second->addTalker(destination_mac);
               search3->second->addTalker(transmitter_mac);
             }
           }*/
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
  //Forza arp del repeater per wifi_repeater.pcap
  arp=arp_results;
  //

  u_int packetCount = 0;
  int returnValue;
    while ((returnValue = pcap_next_ex(pcap, &header, &data) >= 0) /*&& (packetCount<10)*/){
      // Show the packet number
      printf("Packet # %i\n", ++packetCount);
      dissectpacket(NULL,header,data);
    }
  std::cout << "Stampa di packResults" << std::endl;
  packResults();
/*
  printf("Stampa finale\n");
  printf("Size :%lu\n", devices.size());
      for( const auto& n : devices ) {
      std::cout << "=====================================" << std::endl;
      std::cout << "Key:[" << n.first << "]" << std::endl;
      n.second->Print();
      std::cout << "=====================================" << std::endl;
  }*/
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
    std::cout << n->getDeviceMAC() << " " << n->getDeviceSSID() << std::endl;
    std::string mac = n->getDeviceMAC();
    checkLocalAdministered(mac);
/*
    for(auto v : n->talkers){
      //std::cout << v.getDeviceMAC() << " " << v.getDeviceSSID() << std::endl;
      std::string mac = v;
      checkLocalAdministered(mac);
  }*/
}
/*  for(const auto i : devices){
    if(i.second->isLocallyAdministered){
      findGloballyAdministeredInterface(i.second->mac_address);
    }
  }*/

  for( const auto n : ap ){
    findMainMACAP(n->getDeviceMAC());
  }
  //Spostato da sopra
  for(const auto i : devices){
      if(i.second->isLocallyAdministered){
        findGloballyAdministeredInterface(i.second->mac_address);
    }
  }
  /*
/*
  for( const auto n : devices ){
    findMainMACAP(n.second->getDeviceMAC());
  }*/

}

void RadiotapScanner::startScan(int time){
  alarm(time);
  signal(SIGALRM, RadiotapScanner::alarmHandler);
  pcap_loop(handle,0,dissectpacket,NULL);
}

void RadiotapScanner::alarmHandler(int sig){
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
        if(search->second->main_device!=NULL){
          k = search->second->main_device->getDeviceMAC();
        }
        if(k==d.mac_wifidevice){
          continue;
        }
        if(std::find(d.connected.begin(), d.connected.end(), k) == d.connected.end()){
          d.connected.push_back(k);
        }
      }
      for(auto i : n.second->start_point){
        auto search = devices.find(i);
        auto k = search->second->getDeviceMAC();
        if(search->second->main_device!=NULL){
          k = search->second->main_device->getDeviceMAC();
        }
        if(k==d.mac_wifidevice){
          continue;
        }
        if(std::find(d.connected.begin(), d.connected.end(), k) == d.connected.end()){
          d.connected.push_back(k);
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
      }
      std::list<pc_wifi>::iterator it;
      bool found=false;
      for( it = pc_list.begin() ; it != pc_list.end() ; it++){
        if(pc.mac_pc==it->mac_pc){
          found=true;
        }
      }
      if(!found){
        pc_list.push_back(pc);
      }
      //pc_list.push_back(pc);
    }
  }
  WiFiResult *toreturn = new WiFiResult(device_list,pc_list);
  return toreturn;
}
