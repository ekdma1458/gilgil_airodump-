#include "airodump.h"

void usage() {
    cout << "syntax: airodump <interface>" << endl;
    cout << "sample: airodump mon0" << endl;
}

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i % 16 == 0){
            printf("\n");
        }
        printf("%02x ", buf[i]);
    }
    printf("\n");
}

void printApDump(map<ID, st_je_ap_header> ap_info){
    printf("%-17s\t%s\t%s\t%s\t%s\t%-5s\t%s\r\n","ID","PWR","Beacons","#Data","CH","ENC","ESSID");
    for (auto it = ap_info.begin(); it != ap_info.end(); it++){
        //printf("%-17s\t%s\t%s\t%s\t%s\t%-5s\t%s\r\n",it->second.bssid, it->second.pwr,it->second.beacons,"#Data",it->second.ch, it->second.enc, it->second.essid.c_str());
    }
    printf("\r\n");
}

void printApToStaion(map<pair<ID, ID>, uint64_t> ip_a_to_b){
    printf("%-17s\t%-17s\t%s\r\n","ID","STATION","Frames(Count)");
    for (auto it=ip_a_to_b.begin(); it != ip_a_to_b.end(); it++){
        //printID(it->first.first);
        //printID(it->first.second);
        //printf("%d\r\n",it->second);
    }
}
void printID(string id){
    for (int i = 0; i < 5; i++) {
        //printf("%02x:", id.id[i]);
        if(i==4){
          //  printf("%02x\t", id.id[i]);
            break;
        }
    }
}
