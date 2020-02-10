#include "stdafx.h"
#include <radiotap-library/radiotap.h>

int main(int argc, char *argv[])
{
    if(argc < 2){
        usage();
        return 0;
    }

////////////////////////////////offline
    /*
    char errbuffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(argv[1], errbuffer);

    //you don't have file
    if (handle == nullptr) {
        fprintf(stderr, "%s", errbuffer);
        return -1;
    }
*/


////////////////////////////////live


    char errbuffer[PCAP_ERRBUF_SIZE];

    pcap_t *handle;

     handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuffer);
     if (handle == NULL) {
         fprintf(stderr, "Couldn't open device %s: %s\n", argv[1], errbuffer);
         return(2);
     }

     const u_char* packet;



/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


    map<ID, st_je_ap_header> ap_info;
    map<pair<ID, ID>, uint32_t> ip_a_to_b;
    time_t current = time(0);


    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        ieee80211_radiotap_header* radio_header = reinterpret_cast<ieee80211_radiotap_header*>(const_cast<u_char*>(packet));

        uint32_t pw_pointer = sizeof(ieee80211_radiotap_header);

        st_je_ap_header temp;
        temp.ch = 0;
        temp.pwr = 0;
        temp.beacons = 1;
        temp.data = 0;
        temp.enc = 0;
        if (radio_header->it_present & 0x80000000){
            pw_pointer += 4;
            while(*reinterpret_cast<uint32_t*>(const_cast<u_char*>(packet + pw_pointer)) & (1 << IEEE80211_RADIOTAP_EXT)) {
                pw_pointer += 4;
            }
        }
        if(radio_header->it_present & (1 << IEEE80211_RADIOTAP_TSFT)){
            pw_pointer += 8;
        }
        if(radio_header->it_present & (1 << IEEE80211_RADIOTAP_FLAGS)){
            pw_pointer += 1;
        }
        if(radio_header->it_present & (1 << IEEE80211_RADIOTAP_RATE)){
            pw_pointer += 1;
        }
        if(radio_header->it_present & (1 << IEEE80211_RADIOTAP_CHANNEL)){
            pw_pointer += 4;
        }
        if(radio_header->it_present & (1 << IEEE80211_RADIOTAP_FHSS)){
            pw_pointer += 2;
        }
        if(radio_header->it_present & (1 << IEEE80211_RADIOTAP_DBM_ANTSIGNAL)){
            temp.pwr = *reinterpret_cast<int8_t*>(const_cast<u_char*>(packet + pw_pointer));
        }

        st_je_802_header *je_mac_frame = reinterpret_cast<st_je_802_header*>(const_cast<u_char*>(packet + radio_header->it_len));
        memcpy(temp.bssid, je_mac_frame->bssid, 6);

        if(ntohs(je_mac_frame->FC) == 0x8000){
            uint32_t checker = 0;
            //12 is fixed param
            checker += radio_header->it_len + sizeof(st_je_802_header) + 12;
            char bssid[255] = {0};
            memcpy(bssid, packet + checker + 2, *(packet + checker + 1));
            if (bssid[0] == 0){
                temp.essid = string("length : " + to_string(*(packet + checker + 1)));
            }else {
                temp.essid = string(bssid);
            }
            checker += *(packet + checker + 1 ) + 2;

            while(header->len > checker){
                if(*(packet + checker) == 0x03){
                    temp.ch = *(packet + checker + 2);
                    checker += *(packet + checker + 1) + 2;
                }
                if(*(packet + checker) == 0xdd){
                    if(*(packet + checker + 2 + 3) == 0x01){
                        temp.enc = 1;
                        temp.enc_version = *reinterpret_cast<uint16_t*>(const_cast<u_char*>(packet + checker + 2 + 3 + 1));
                    }
                    checker += *(packet + checker + 1) + 2;
                }
                checker += *(packet + checker + 1) + 2;
            }

            bool ap_info_check = true;

            for(auto it=ap_info.begin();it!=ap_info.end();it++){
                if(it->first == ID(temp.bssid)){
                    it->second.beacons++;
                    it->second.pwr = temp.pwr;
                    it->second.enc = temp.enc;
                    it->second.ch = temp.ch;

                    ap_info_check = false;
                }
            }

            if(ap_info_check){
                ap_info.insert(make_pair(ID(temp.bssid), temp));
            }
        } else if (ntohs(je_mac_frame->FC) & 0x0800) {
            for(auto it=ap_info.begin();it!=ap_info.end();it++){
                if(it->first == ID(temp.bssid)){
                    it->second.data++;
                }
            }
        } else if(ntohs(je_mac_frame->FC) == 0x4000 || ntohs(je_mac_frame->FC) == 0x5000){
            bool ap_staion_check = true;

            for(auto it=ip_a_to_b.begin();it!=ip_a_to_b.end();it++){
                if(it->first.first == ID(je_mac_frame->rec) and it->first.second == ID(je_mac_frame->trs) ){
                    it->second++;
                    ap_staion_check = false;
                }else if(it->first.first == ID(je_mac_frame->trs) and it->first.second == ID(je_mac_frame->rec) ){
                    it->second++;
                    ap_staion_check = false;
                }
            }

            if(ap_staion_check){
                ip_a_to_b.insert(make_pair(make_pair(ID(je_mac_frame->rec),ID(je_mac_frame->trs)), 1));
            }
        }

        if (time(0) - current > 1) {
            system("clear");
            printf("%-17s\t%s\t%s\t%s\t%s\t%-5s\t%s\r\n","ID","PWR","Beacons","#Data","CH","ENC","ESSID");
            for (auto it = ap_info.begin(); it != ap_info.end(); it++){
                printf("%02X:%02X:%02X:%02X:%02X:%02X\t", it->second.bssid[0], it->second.bssid[1], it->second.bssid[2], it->second.bssid[3], it->second.bssid[4], it->second.bssid[5]);
                printf("%d\t%d\t%d\t%d\t%s\t%s\r\n", it->second.pwr,it->second.beacons, it->second.data, it->second.ch, (it->second.enc == 1?"WPA":"OPEN"),it->second.essid.c_str());
            }
            printf("\r\n");
            printf("%-17s\t%-17s\t%s\r\n","ID","STATION","Frames(Count)");
            uint8_t test[] = {0xff,0xff,0xff,0xff,0xff,0xff};
            for (auto it=ip_a_to_b.begin(); it != ip_a_to_b.end(); it++){

                ID id = it->first.first;
                if(id == ID(test)){
                    printf("Broad Cast\t\t", id.getID()[0], id.getID()[1], id.getID()[2], id.getID()[3], id.getID()[4], id.getID()[5]);
                }else{
                    printf("%02X:%02X:%02X:%02X:%02X:%02X\t", id.getID()[0], id.getID()[1], id.getID()[2], id.getID()[3], id.getID()[4], id.getID()[5]);
                }

                ID station = it->first.second;
                if(station == ID(test)){
                    printf("Broad Cast\t\t", station.getID()[0], station.getID()[1], station.getID()[2], station.getID()[3], station.getID()[4], station.getID()[5]);
                }else{
                    printf("%02X:%02X:%02X:%02X:%02X:%02X\t", station.getID()[0], station.getID()[1], station.getID()[2], station.getID()[3], station.getID()[4], station.getID()[5]);
                }
                printf("%d\r\n", it->second);

            }
            current = time(0);
        }
    }

    return 0;
}
