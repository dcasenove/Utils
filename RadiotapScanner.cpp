#include "RadiotapScanner.h"
#include <time.h>
using namespace std;

const uint32_t crctable[] = {
   0x00000000L, 0x77073096L, 0xee0e612cL, 0x990951baL, 0x076dc419L, 0x706af48fL, 0xe963a535L, 0x9e6495a3L,
   0x0edb8832L, 0x79dcb8a4L, 0xe0d5e91eL, 0x97d2d988L, 0x09b64c2bL, 0x7eb17cbdL, 0xe7b82d07L, 0x90bf1d91L,
   0x1db71064L, 0x6ab020f2L, 0xf3b97148L, 0x84be41deL, 0x1adad47dL, 0x6ddde4ebL, 0xf4d4b551L, 0x83d385c7L,
   0x136c9856L, 0x646ba8c0L, 0xfd62f97aL, 0x8a65c9ecL, 0x14015c4fL, 0x63066cd9L, 0xfa0f3d63L, 0x8d080df5L,
   0x3b6e20c8L, 0x4c69105eL, 0xd56041e4L, 0xa2677172L, 0x3c03e4d1L, 0x4b04d447L, 0xd20d85fdL, 0xa50ab56bL,
   0x35b5a8faL, 0x42b2986cL, 0xdbbbc9d6L, 0xacbcf940L, 0x32d86ce3L, 0x45df5c75L, 0xdcd60dcfL, 0xabd13d59L,
   0x26d930acL, 0x51de003aL, 0xc8d75180L, 0xbfd06116L, 0x21b4f4b5L, 0x56b3c423L, 0xcfba9599L, 0xb8bda50fL,
   0x2802b89eL, 0x5f058808L, 0xc60cd9b2L, 0xb10be924L, 0x2f6f7c87L, 0x58684c11L, 0xc1611dabL, 0xb6662d3dL,
   0x76dc4190L, 0x01db7106L, 0x98d220bcL, 0xefd5102aL, 0x71b18589L, 0x06b6b51fL, 0x9fbfe4a5L, 0xe8b8d433L,
   0x7807c9a2L, 0x0f00f934L, 0x9609a88eL, 0xe10e9818L, 0x7f6a0dbbL, 0x086d3d2dL, 0x91646c97L, 0xe6635c01L,
   0x6b6b51f4L, 0x1c6c6162L, 0x856530d8L, 0xf262004eL, 0x6c0695edL, 0x1b01a57bL, 0x8208f4c1L, 0xf50fc457L,
   0x65b0d9c6L, 0x12b7e950L, 0x8bbeb8eaL, 0xfcb9887cL, 0x62dd1ddfL, 0x15da2d49L, 0x8cd37cf3L, 0xfbd44c65L,
   0x4db26158L, 0x3ab551ceL, 0xa3bc0074L, 0xd4bb30e2L, 0x4adfa541L, 0x3dd895d7L, 0xa4d1c46dL, 0xd3d6f4fbL,
   0x4369e96aL, 0x346ed9fcL, 0xad678846L, 0xda60b8d0L, 0x44042d73L, 0x33031de5L, 0xaa0a4c5fL, 0xdd0d7cc9L,
   0x5005713cL, 0x270241aaL, 0xbe0b1010L, 0xc90c2086L, 0x5768b525L, 0x206f85b3L, 0xb966d409L, 0xce61e49fL,
   0x5edef90eL, 0x29d9c998L, 0xb0d09822L, 0xc7d7a8b4L, 0x59b33d17L, 0x2eb40d81L, 0xb7bd5c3bL, 0xc0ba6cadL,
   0xedb88320L, 0x9abfb3b6L, 0x03b6e20cL, 0x74b1d29aL, 0xead54739L, 0x9dd277afL, 0x04db2615L, 0x73dc1683L,
   0xe3630b12L, 0x94643b84L, 0x0d6d6a3eL, 0x7a6a5aa8L, 0xe40ecf0bL, 0x9309ff9dL, 0x0a00ae27L, 0x7d079eb1L,
   0xf00f9344L, 0x8708a3d2L, 0x1e01f268L, 0x6906c2feL, 0xf762575dL, 0x806567cbL, 0x196c3671L, 0x6e6b06e7L,
   0xfed41b76L, 0x89d32be0L, 0x10da7a5aL, 0x67dd4accL, 0xf9b9df6fL, 0x8ebeeff9L, 0x17b7be43L, 0x60b08ed5L,
   0xd6d6a3e8L, 0xa1d1937eL, 0x38d8c2c4L, 0x4fdff252L, 0xd1bb67f1L, 0xa6bc5767L, 0x3fb506ddL, 0x48b2364bL,
   0xd80d2bdaL, 0xaf0a1b4cL, 0x36034af6L, 0x41047a60L, 0xdf60efc3L, 0xa867df55L, 0x316e8eefL, 0x4669be79L,
   0xcb61b38cL, 0xbc66831aL, 0x256fd2a0L, 0x5268e236L, 0xcc0c7795L, 0xbb0b4703L, 0x220216b9L, 0x5505262fL,
   0xc5ba3bbeL, 0xb2bd0b28L, 0x2bb45a92L, 0x5cb36a04L, 0xc2d7ffa7L, 0xb5d0cf31L, 0x2cd99e8bL, 0x5bdeae1dL,
   0x9b64c2b0L, 0xec63f226L, 0x756aa39cL, 0x026d930aL, 0x9c0906a9L, 0xeb0e363fL, 0x72076785L, 0x05005713L,
   0x95bf4a82L, 0xe2b87a14L, 0x7bb12baeL, 0x0cb61b38L, 0x92d28e9bL, 0xe5d5be0dL, 0x7cdcefb7L, 0x0bdbdf21L,
   0x86d3d2d4L, 0xf1d4e242L, 0x68ddb3f8L, 0x1fda836eL, 0x81be16cdL, 0xf6b9265bL, 0x6fb077e1L, 0x18b74777L,
   0x88085ae6L, 0xff0f6a70L, 0x66063bcaL, 0x11010b5cL, 0x8f659effL, 0xf862ae69L, 0x616bffd3L, 0x166ccf45L,
   0xa00ae278L, 0xd70dd2eeL, 0x4e048354L, 0x3903b3c2L, 0xa7672661L, 0xd06016f7L, 0x4969474dL, 0x3e6e77dbL,
   0xaed16a4aL, 0xd9d65adcL, 0x40df0b66L, 0x37d83bf0L, 0xa9bcae53L, 0xdebb9ec5L, 0x47b2cf7fL, 0x30b5ffe9L,
   0xbdbdf21cL, 0xcabac28aL, 0x53b39330L, 0x24b4a3a6L, 0xbad03605L, 0xcdd70693L, 0x54de5729L, 0x23d967bfL,
   0xb3667a2eL, 0xc4614ab8L, 0x5d681b02L, 0x2a6f2b94L, 0xb40bbe37L, 0xc30c8ea1L, 0x5a05df1bL, 0x2d02ef8dL
};

uint32_t crc32(uint32_t bytes_sz, const uint8_t *bytes)
{
   uint32_t crc = ~0;
   uint32_t i;
   for(i = 0; i < bytes_sz; ++i) {
      crc = crctable[(crc ^ bytes[i]) & 0xff] ^ (crc >> 8);
   }
   return ~crc;
}


template<typename TInputIter>
std::string make_hex_string(TInputIter first, TInputIter last, bool use_uppercase = true, bool insert_spaces = false)
{
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

    return true;
}

int ieee80211_mhz_to_chan(unsigned int freq) {
    unsigned int i;

    for (i = 0; i < NUM_FREQ_CVT; i++) {
        if (freq >= freq_cvt[i].fmin && freq <= freq_cvt[i].fmax) {
            return ((freq - freq_cvt[i].fmin) / FREQ_STEP) + freq_cvt[i].cmin;
        }
    }
    return -1;
}

static void print_radiotap_namespace(struct ieee80211_radiotap_iterator *iter,struct signal_power *power){
	switch (iter->this_arg_index) {
	case IEEE80211_RADIOTAP_TSFT:
		printf("\tTSFT : %llu\n", le64toh(*(unsigned long long *)iter->this_arg));
		break;
	case IEEE80211_RADIOTAP_FLAGS:
		printf("\tFlags : %02x\n", *iter->this_arg);
		break;
	case IEEE80211_RADIOTAP_RATE:
		printf("\tRate : %lf\n", (double)*iter->this_arg/2);
		break;
	case IEEE80211_RADIOTAP_CHANNEL:
        //Funziona, vedere little/big endian
        printf("\tChannel : %d\n",ieee80211_mhz_to_chan(le16toh(*(unsigned int *) iter->this_arg)));
        printf("\tChannel Frequency : %u\n", le16toh(*(unsigned int *)iter->this_arg));
        power->channel=ieee80211_mhz_to_chan(le16toh(*(unsigned int *) iter->this_arg));
        break;
	case IEEE80211_RADIOTAP_FHSS:
	case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
  //Qui
        power->antenna_signal=*iter->this_arg;
        printf("\tSignal : %d\n",(signed char) *iter->this_arg);
        break;

	case IEEE80211_RADIOTAP_DBM_ANTNOISE:
        power->antenna_noise=*iter->this_arg;
        printf("\tNoise : %d\n", (signed char)*iter->this_arg);
        break;

	case IEEE80211_RADIOTAP_LOCK_QUALITY:
	case IEEE80211_RADIOTAP_TX_ATTENUATION:
	case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
	case IEEE80211_RADIOTAP_DBM_TX_POWER:
	case IEEE80211_RADIOTAP_ANTENNA:
        printf("\tAntenna : %d\n",(signed char) *iter->this_arg);
        break;

	case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
        printf("\tSignal : %d\n",(signed char) *iter->this_arg);
        break;
	case IEEE80211_RADIOTAP_DB_ANTNOISE:
        printf("\tNoise : %d\n", (signed char)*iter->this_arg);
        break;
	case IEEE80211_RADIOTAP_TX_FLAGS:
		break;
	case IEEE80211_RADIOTAP_RX_FLAGS:
		if (fcshdr) {
			printf("\tFCS in header : %.8x\n",
				le32toh(*(uint32_t *)iter->this_arg));
			break;
		}
		printf("\tRX flags : %#.4x\n",
			le16toh(*(uint16_t *)iter->this_arg));
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


    err=ieee80211_radiotap_iterator_init(&iter, (ieee80211_radiotap_header*)packet, header->len, &vns);
    if(err){
        cout << ("Malformed header") << endl;
        return;
    }
    cout << ("Init valido") << endl;
    printf("===RADIOTAP HEADER===\n");
    	while (!(err = ieee80211_radiotap_iterator_next(&iter))) {
		if (iter.this_arg_index == IEEE80211_RADIOTAP_VENDOR_NAMESPACE) {
			printf("\tvendor NS (%.2x-%.2x-%.2x:%d, %d bytes)\n",
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
			printf("\n");
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
    std::cout << "Prova " << power.antenna_signal << power.antenna_noise  << power.timestamp<< std::endl;
    printf("\tSignal : %d\n",(signed char) power.antenna_signal);
    printf("\Noise : %d\n",(signed char) power.antenna_noise);

    std::cout << "Dopo prova";

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

    frame80211 = (ieee80211mac *) (packet+radiotapheader->it_len/*SIZERADIOTAP*/);
    ctl = (framectl_bits *)&frame80211->framectl;
    printf("\tProtocol version : %u\n", ctl->protocol_version);
    printf("\tType : %u\n", ctl->type);
    printf("\tSubtype : %u\n", ctl->subtype);
    printf("\tDuration :%u\n", frame80211->duration);
    printf("===802.11===\n");
   // printf("\tReceiver : ");
/*    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", frame80211->receiver[0],frame80211->receiver[1],frame80211->receiver[2],frame80211->receiver[3],
            frame80211->receiver[4],frame80211->receiver[5]);
    printf("\tTransmitter : ");
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", frame80211->transmitter[0],frame80211->transmitter[1],frame80211->transmitter[2],frame80211->transmitter[3],
            frame80211->transmitter[4],frame80211->transmitter[5]);
    printf("\tDestination : ");
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", frame80211->destination[0],frame80211->destination[1],frame80211->destination[2],frame80211->destination[3],
            frame80211->destination[4],frame80211->destination[5]);
*/
    //Beacon Frame
    if(ctl->type == 0){
        printf("\nManagement frame\n");
        if(ctl->subtype == 8){
            struct beacon_frame *bframe;
            bframe = (beacon_frame *)(packet+radiotapheader->it_len/*SIZERADIOTAP*//*+SIZEBEACONFRAME*/);
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
          //  Device* d = new Device(bframe);
          //  if(devices.contains(d->mac_address)){
          //      devices.find(d->mac_address);
          //  }
          //  devices.insert({d->mac_address,d});
     //       devices.push_back(*d);
     //
     //     Cerco se ho gia' un device creato con il mac address
     //     Se positivo controllo che sia stato gia' ricevuto un pacchetto beacon e settato come AP
          //  std::string t(bframe->transmitter, bframe->transmitter+6);
           // std::string transmitter_mac = new string;
            auto transmitter_mac = make_hex_string(std::begin(bframe->transmitter), std::end(bframe->transmitter), false,  true);
            std::cout << "Il risultato della funzione e' : " << transmitter_mac << endl;
            auto search = devices.find(transmitter_mac);
           // auto search = devices.find(bframe->transmitter);
            if(search!=devices.end()){
                std::cout << "Trovato,setto beacon";
                if(!search->second->isAP){
                    search->second->setAP(bframe->length,bframe->ssid);
                    search->second->addPowerValues(power);
                }
            }
            else{
                std::cout << "Non trovato, aggiungo beacon";
                Device* d = new Device(transmitter_mac);
                d->setAP(bframe->length,bframe->ssid);
                d->addPowerValues(power);
            //    std::string s(d->mac_address, d->mac_address+6);
                devices.insert({transmitter_mac,d});
            }
            return;

        }
        if(ctl->subtype == 1){
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
        if(ctl->subtype == 10){

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
              search2->second->removeTalker(transmitter_mac);
            }
            return;
        }

        if(ctl->subtype == 12){

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
            search2->second->removeTalker(transmitter_mac);
          }
        return;
        }
    }
    if(ctl->type == 1){
        printf("\nControl frame\n");
        struct control_frames *frame;
        if(ctl->subtype == 8){
             printf("Block ack req");
         //    struct control_frames *frame;
             frame = (control_frames *)(packet+radiotapheader->it_len/*SIZERADIOTAP*/);
             printf("Block ack\n");
             printf("\tReceiver : ");
             printf("%02x:%02x:%02x:%02x:%02x:%02x\n", frame->receiver[0],frame->receiver[1],
                      frame->receiver[2],frame->receiver[3],frame->receiver[4],
                      frame->receiver[5]);
             printf("\tTransmitter : ");
             printf("%02x:%02x:%02x:%02x:%02x:%02x\n", frame->transmitter[0],frame->transmitter[1],
                      frame->transmitter[2],frame->transmitter[3],frame->transmitter[4],
                      frame->transmitter[5]);
        }

        if(ctl->subtype == 0){
          printf("Reserved \n");
          return;
        }
        if(ctl->subtype == 4){
          printf("Beamforming \n");
          return;
        }

        if(ctl->subtype == 7){
          printf("Control wrapper \n");
          return;
        }
        if(ctl->subtype == 9){
        //    struct control_frames *frame;
            frame = (control_frames *)(packet+radiotapheader->it_len/*SIZERADIOTAP*/);
            printf("Block ack\n");
            printf("\tReceiver : ");
            printf("%02x:%02x:%02x:%02x:%02x:%02x\n", frame->receiver[0],frame->receiver[1],
                     frame->receiver[2],frame->receiver[3],frame->receiver[4],
                     frame->receiver[5]);
            printf("\tTransmitter : ");
            printf("%02x:%02x:%02x:%02x:%02x:%02x\n", frame->transmitter[0],frame->transmitter[1],
                     frame->transmitter[2],frame->transmitter[3],frame->transmitter[4],
                     frame->transmitter[5]);
          //  printf("\tBlockAck Control : %u\n", frame->blockack_control);
        }
        if(ctl->subtype == 11){
            printf("RTS\n");
     //       struct control_frames *frame;
            frame = (control_frames *)(packet+radiotapheader->it_len/*SIZERADIOTAP*/);
            printf("\tReceiver : ");
            printf("%02x:%02x:%02x:%02x:%02x:%02x\n", frame->receiver[0],frame->receiver[1],
                    frame->receiver[2],frame->receiver[3],frame->receiver[4],
                    frame->receiver[5]);
            printf("\tTransmitter : ");
            printf("%02x:%02x:%02x:%02x:%02x:%02x\n", frame->transmitter[0],frame->transmitter[1],
                    frame->transmitter[2],frame->transmitter[3],frame->transmitter[4],
                    frame->transmitter[5]);
        }
        if(ctl->subtype == 12){
            printf("Clear to send\n");
            return;
        }
        if(ctl->subtype == 13){
            printf("Ack\n");
            return;
        }
       // auto search = devices.find(frame->transmitter);
//                       std::string t(frame->transmitter, frame->transmitter+6);

        //auto search = devices.find(t);
        auto transmitter_mac = make_hex_string(std::begin(frame->transmitter), std::end(frame->transmitter), false,  true);
        auto search = devices.find(transmitter_mac);
        std::cout << "Cerco";
        if(search == devices.end()){
            //printf("Non trovato, aggiungo\n");
            std::cout << "Non trovato,aggiungo" << std::endl;
            if(isValidMAC(transmitter_mac)){
                Device *d = new Device(transmitter_mac);
                devices.insert({transmitter_mac,d});
            }
            //Device *d = new Device(frame->transmitter);
           // devices.insert({t,d});
         //   Device *d = new Device(/*frame*/ frame->transmitter);
         //   devices.insert({d->mac_address,d});
        }
        auto receiver_mac = make_hex_string(std::begin(frame->receiver), std::end(frame->receiver), false,  true);
        auto search2= devices.find(receiver_mac);
        //std::string r(frame->receiver, frame->receiver+6);
        //auto search2= devices.find(r);
        if(search2 == devices.end()){
            if(isValidMAC(receiver_mac)){
                Device *d = new Device(receiver_mac);
                d->addPowerValues(power);
                devices.insert({receiver_mac,d});
            }
           // Device *d = new Device(frame->receiver);
           // devices.insert({r,d});
        }
//        search = devices.find(frame->receiver);
//        if(search == devices.end()){
//            Device *d = new Device(/*frame*/frame->receiver);
//            devices.insert({d->mac_address,d});
//        }

      //Non e' qui
        if(transmitter_mac.compare(receiver_mac)!=0){
        search = devices.find(transmitter_mac);
        search2 = devices.find(receiver_mac);
        if(search!=devices.end() && search2!=devices.end()){
        if(!search2->second->isTalking(transmitter_mac)){
            search->second->addTalker(receiver_mac);
            search2->second->addTalker(transmitter_mac);
            search2->second->addPowerValues(power);
        }
      }

    }
  }
    if(ctl->type == 2){
        printf("\nData frame\n");
        if(ctl->subtype == 0){
            printf("Data\n");
        }
        if(ctl->subtype == 4){
            printf("Null no data\n");
        }

        if(ctl->subtype == 8){
            printf("QoS data\n");
        }
        if(ctl->subtype == 12){
            printf("QoS null no data\n");
        }
        struct data_frames *frame;
        frame = (data_frames *)(packet+radiotapheader->it_len/*SIZERADIOTAP*/);

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
  //              std::string t(frame->transmitter, frame->transmitter+6);
  //              auto search = devices.find(t);
            auto transmitter_mac = make_hex_string(std::begin(frame->transmitter), std::end(frame->transmitter), false,  true);
            auto search = devices.find(transmitter_mac);
         std::cout << "Cerco";
         if(search == devices.end()){
             //printf("Non trovato, aggiungo\n");
             std::cout << "Non trovato,aggiungo" << std::endl;
             if(isValidMAC(transmitter_mac)){
                Device *d = new Device(transmitter_mac);
                devices.insert({transmitter_mac,d});
             }
           //  Device *d = new Device(frame->transmitter);
           //  devices.insert({t,d});
          //   Device *d = new Device(/*frame*/ frame->transmitter);
          //   devices.insert({d->mac_address,d});
         }
        auto receiver_mac = make_hex_string(std::begin(frame->receiver), std::end(frame->receiver), false,  true);
        auto search2 = devices.find(receiver_mac);
         //std::string r(frame->receiver, frame->receiver+6);
         //auto search2= devices.find(r);
         if(search2 == devices.end()){
             if(isValidMAC(receiver_mac)){
          Device *d = new Device(receiver_mac);
          d->addPowerValues(power);

          devices.insert({receiver_mac,d});
             }
             //   Device *d = new Device(frame->receiver);
          //   devices.insert({r,d});
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
    }
    }
}

RadiotapScanner::RadiotapScanner(){
  //Lookup device
  device = pcap_lookupdev(errbuf);
  if(device == NULL){
      cout << ("Device di rete non trovato\n");
    //  return 1;
  }
  cout << ("Device scelto : ") << device << endl;

  //Get Netmask
  if(pcap_lookupnet(device, &network, &mask, errbuf) == -1) {
   cout << ("Errore netmask del device") << device << endl;
   network = 0;
   mask = 0;
  }

  //Create and set up device
  handle = pcap_create(device, errbuf);
  //Monitor mode
  pcap_set_rfmon(handle, 1);
  //Promiscous mode
  pcap_set_promisc(handle, 1);
  //Snaplen
  pcap_set_snaplen(handle, 2048);
  //Timeout
  pcap_set_timeout(handle, 1000);

  pcap_activate(handle);

  //Compile filter
  if(pcap_compile(handle,&fp,filter,0,network) == PCAP_ERROR){
      cout << ("Errore compile filtro") << filter << endl;
      cout << pcap_geterr(handle);
    //  return 1;
  }

  //Set filter
  if(pcap_setfilter(handle,&fp) == -1){
      cout << ("Errore set filtro") << endl;
    //  return 1;
  }

}

RadiotapScanner::RadiotapScanner(char *arg){
  string file;
  file=arg;
  pcap_t * pcap = pcap_open_offline(file.c_str(), errbuf);
  struct pcap_pkthdr *header;
  const u_char *data;
  u_int packetCount = 0;
  int returnValue;
      while ((returnValue = pcap_next_ex(pcap, &header, &data) >= 0) /*&& (packetCount<10)*/)
  {
      // Show the packet number
      printf("Packet # %i\n", ++packetCount);
      dissectpacket(NULL,header,data);
  }
/*
  printf("Stampa finale\n");
  printf("Size :%lu\n", devices.size());
      for( const auto& n : devices ) {
      std::cout << "=====================================" << std::endl;
      std::cout << "Key:[" << n.first << "]" << std::endl;
      n.second->Print();
      std::cout << "=====================================" << std::endl;
  }*/
}
void RadiotapScanner::startScan(){
  pcap_loop(handle,NPACKETS,dissectpacket,NULL);
}
void RadiotapScanner::close(){
  pcap_set_rfmon(handle,0);
  pcap_set_promisc(handle,0);
  pcap_freecode(&fp);
  pcap_close(handle);
}

std::unordered_map<std::string,Device*> RadiotapScanner::getResult(){
  return devices;
}
