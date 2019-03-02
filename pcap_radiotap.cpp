#include <iostream>
#include <string>
extern "C"{
    #include <pcap.h>
    #include <string.h>
    #include "radiotap_iter.h"
    #include <machine/endian.h>
    #if defined(__APPLE__)
    #else
    #include <endian.h>
    #endif

}

#define NPACKETS 10
#define SIZERADIOTAP 25
#define SIZEBEACONFRAME 24
//Frequency

typedef struct freq_cvt_s {
    unsigned int fmin;         /* Minimum frequency in MHz */
    unsigned  fmax;            /* Maximum frequency in MHz */
    int cmin;                  /* Minimum/base channel */
    bool is_bg;                /* B/G channel? */
} freq_cvt_t;

#define FREQ_STEP 5     /* MHz. This seems to be consistent, thankfully */

static freq_cvt_t freq_cvt[] = {
    { 2412, 2472,   1, true },
    { 2484, 2484,  14, true },
    { 5000, 5995,   0, false },
    { 4910, 4980, 182, false }
};

#define NUM_FREQ_CVT (sizeof(freq_cvt) / sizeof(freq_cvt_t))
#define MAX_CHANNEL(fc) ( (gint) ((fc.fmax - fc.fmin) / FREQ_STEP) + fc.cmin )

//
//
struct mac_addr {
   unsigned char bytes[6];
};


struct ieee80211mac {
    //unsigned int
    u_int16_t framectl;
    u_int16_t duration;
    u_int8_t  receiver[6];
    u_int8_t  transmitter[6];
    u_int8_t  destination[6];
    u_int16_t seq_control;
};

struct framectl_bits{
    unsigned short protocol_version:2;
    unsigned short  type:2;
    unsigned short subtype:4;
    unsigned short to_ds:1;
    unsigned short from_ds:1;
    unsigned short more_frag:1;
    unsigned short retry:1;
    unsigned short pwr_mngmt:1;
    unsigned short more_data:1;
    unsigned short prot_frame:1;
    unsigned short order:1;
};

struct beacon_frame{
    u_int64_t timestamp;
    u_int16_t beacon_interval;
    u_int16_t capability_info;
    u_int8_t  tag;
    u_int8_t  length;
    char ssid[32];
};

int ieee80211_mhz_to_chan(unsigned int freq) {
    unsigned int i;

    for (i = 0; i < NUM_FREQ_CVT; i++) {
        if (freq >= freq_cvt[i].fmin && freq <= freq_cvt[i].fmax) {
            return ((freq - freq_cvt[i].fmin) / FREQ_STEP) + freq_cvt[i].cmin;
        }
    }
    return -1;
}

static int fcshdr = 0;

static const struct radiotap_align_size align_size_000000_00[] = {
	[0] = { .align = 1, .size = 4, },
	[52] = { .align = 1, .size = 4, },
};

static const struct ieee80211_radiotap_namespace vns_array[] = {
	{
		.oui = 0x000000,
		.subns = 0,
		.n_bits = sizeof(align_size_000000_00),
		.align_size = align_size_000000_00,
	},
};

static const struct ieee80211_radiotap_vendor_namespaces vns = {
	.ns = vns_array,
	.n_ns = sizeof(vns_array)/sizeof(vns_array[0]),
};

static void print_radiotap_namespace(struct ieee80211_radiotap_iterator *iter){
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
        break;
	case IEEE80211_RADIOTAP_FHSS:
	case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
        printf("\tSignal : %d\n",(signed char) *iter->this_arg);
        break;

	case IEEE80211_RADIOTAP_DBM_ANTNOISE:
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
/*
static void print_test_namespace(struct ieee80211_radiotap_iterator *iter)
{
	switch (iter->this_arg_index) {
	case 0:
	case 52:
		printf("\t00:00:00-00|%d: %.2x/%.2x/%.2x/%.2x\n",
			iter->this_arg_index,
			*iter->this_arg, *(iter->this_arg + 1),
			*(iter->this_arg + 2), *(iter->this_arg + 3));
		break;
	default:
		printf("\tBOGUS DATA - vendor ns %d\n", iter->this_arg_index);
		break;
	}
}
*/
using namespace std;

void dissectpacket(u_char *args, const struct pcap_pkthdr *header,const u_char *packet){
    struct ieee80211_radiotap_iterator iter;

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
			print_radiotap_namespace(&iter);
//		else if (iter.current_namespace == &vns_array[0])
//			print_test_namespace(&iter);
	}

	if (err != -ENOENT) {
		printf("Radiotap malformato\n");
		return ;
	}
    
    struct ieee80211mac *frame80211;
    struct framectl_bits *ctl;

    frame80211 = (ieee80211mac *) (packet+SIZERADIOTAP);
    ctl = (framectl_bits *)&frame80211->framectl;
    printf("\tProtocol version : %u\n", ctl->protocol_version);
    printf("\tType : %u\n", ctl->type);
    printf("\tSubtype : %u\n", ctl->subtype);
    printf("\tDuration :%u\n", frame80211->duration);
    printf("===802.11 MAC===\n");
    printf("\tReceiver : ");
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", frame80211->receiver[0],frame80211->receiver[1],frame80211->receiver[2],frame80211->receiver[3],
            frame80211->receiver[4],frame80211->receiver[5]);
    printf("\tTransmitter : ");
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", frame80211->transmitter[0],frame80211->transmitter[1],frame80211->transmitter[2],frame80211->transmitter[3],
            frame80211->transmitter[4],frame80211->transmitter[5]);
    printf("\tDestination : ");
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", frame80211->destination[0],frame80211->destination[1],frame80211->destination[2],frame80211->destination[3],
            frame80211->destination[4],frame80211->destination[5]);
    

    //Beacon Frame
    if((ctl->type == 0)&&(ctl->subtype==8)){
        struct beacon_frame *bframe;
        bframe = (beacon_frame *)(packet+SIZERADIOTAP+SIZEBEACONFRAME);
        printf("\tTimestamp : %llu\n", bframe->timestamp);
        printf("\tBeacon Interval : %u TU\n", bframe->beacon_interval);
        printf("\tCapability info : %u\n", bframe->capability_info);
        printf("\tSSID Length : %u\n", bframe->length);
        bframe->ssid[bframe->length]='\0';
        printf("\tSSID = %s\n", bframe->ssid);
       // *bframe->ssid=(char  )malloc(sizeof(char)*bframe->length);
       // char *ssid = (char *) malloc(sizeof(char) * bframe->length+1);
       // char * c = (char *)(bframe+15);
        //printf("%s\n", c);
        //strncpy(ssid,(char *) (bframe+15),(int) bframe->length);
        //memcpy(ssid,bframe+15,bframe->length);
        //ssid[bframe->length+1]='\0';
        //printf("\tSSID name : %s", ssid);
        //free(ssid);
        //for(int i=0;i<bframe->length;i++){
        //    printf("%s", (char *)(bframe+14+i));
        //}
    }
}


int main(int argc, char *argv[]){
   
    char *device, errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    char filter[]="type mgt subtype beacon";
    //char filter[] = "type data";
    struct bpf_program fp;

    bpf_u_int32 mask;
    bpf_u_int32 network;

    //Lookup device
    device = pcap_lookupdev(errbuf);
    if(device == NULL){
        cout << ("Device di rete non trovato\n");
        return 1;
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
        return 1;
    }
    
    //Set filter
    if(pcap_setfilter(handle,&fp) == -1){
        cout << ("Errore set filtro") << endl;
        return 1;
    }
    
    //Loop 
    pcap_loop(handle,NPACKETS,dissectpacket,NULL);

    //Clean up

    pcap_set_rfmon(handle,0);
    pcap_set_promisc(handle,0);
    
    pcap_freecode(&fp);
    pcap_close(handle);
    
    return 0;
}
