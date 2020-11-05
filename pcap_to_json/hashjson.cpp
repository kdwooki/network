#include <iostream>
#include <string.h>
#include <string>
#include <cstring>
#include <sys/time.h>
#include <netinet/in.h>  
#include <net/ethernet.h>  
#include <pcap.h>  
#include <time.h>
#include <signal.h>
#include <stdio.h>  
#include <stdlib.h>  
#include <string.h>
#include <errno.h>  
#include <unistd.h>  
#include <netinet/ip.h>  
#include <netinet/tcp.h>  
#include <netinet/udp.h>  
#include <netinet/ip_icmp.h>  
#include <unordered_set>
#define _CRT_SECURE_NO_WARNINGS
using namespace std;

struct ip *iph;
struct tcphdr *tcph;
struct udphdr *udph;
char *indexname;

unordered_set<string> pcap_set;
int count; // 패킷의 개수
int counteth; // non IP type ethernet의 개수

long sttime; // PCAP FILE 안의 패킷의 처음 시작 시간
long entime; // PCAP FILE 안의 패킷의 마지막 시간

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet);

int main(int argc, char *argv[])
{
    clock_t start = clock();
    char errbuf[PCAP_ERRBUF_SIZE];
    char *pfname = argv[1];
    char *indexname = argv[2];
    char *jfname = argv[3];
   
    pcap_t *pcd;
    count = 0;
    counteth = 0;
    pcd = pcap_open_offline(pfname, errbuf);
    if (pcd == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }
    pcap_loop(pcd, 0, callback, NULL);
    clock_t end = clock();
    printf("Time: %lf\n", (double)(end -start)/CLOCKS_PER_SEC);
    printf("total packets: %d, pcap set size: %d, non IP type count: %d\n", (int) count, (int)pcap_set.size(), (int)counteth); 
    
    FILE *fp = fopen(jfname, "w"); // json으로 저장할 파일 open
    
    // 아래는 onordered set에서 string을 ,로 나누어 각각의 정보들을 json으로 저장하는 과정
    int str_cnt;
    string a; 
    string str_arr[7]; // 나눠진 각각의 정보들을 담을 배열 선언
    for (auto itr = pcap_set.begin(); itr != pcap_set.end(); itr++) 
    { 
	str_cnt = 0;
	a = *itr;
	char *cstr = new char[a.length()+1];
	strcpy (cstr, a.c_str());
	char *tok = strtok(cstr, ",");
	while(tok != NULL)
	{
	    str_arr[str_cnt++] = string(tok); // 배열에 나누어진 정보들을 담기
	    tok = strtok(NULL, ",");
	}
    // es에 bulk json 할 양식으로 저장
	fprintf(fp, "{\"index\":{\"_index\":\"%s\"}}\n", indexname);
	fprintf(fp, "{\"start_time\":\"%ld\",", sttime);
	fprintf(fp, "\"end_time\":\"%ld\",", entime);
	fprintf(fp, "\"path\":\"%s\",", pfname );
	fprintf(fp, "\"Src_Address\":\"%s\",", str_arr[0].c_str());
	fprintf(fp, "\"Src_Port\":\"%s\"," , str_arr[1].c_str());
	fprintf(fp, "\"Dst_Address\":\"%s\",", str_arr[2].c_str());
	fprintf(fp, "\"Dst_Port\":\"%s\"," , str_arr[3].c_str());
	fprintf(fp, "\"protocol_type_number\":\"%s\"}\n", str_arr[4].c_str());

    }

    return 0;
}

// PCAP FILE을 파싱 후 정보들을 하나의 string으로 만들어 unordered set을 사용하여 중복을 제거하는 함수
void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{   
    struct ether_header *ep;
    unsigned short ether_type;
    int length=pkthdr->len;
    ep = (struct ether_header *)packet;
    packet += sizeof(struct ether_header);

    string tmp;
    string sa;
    string sp;
    string da;
    string dp;
    string type;

    // PCAP FILE의 시작 시간은 처음 패킷의 시간정보
    if(count == 0) { sttime = (long)pkthdr->ts.tv_sec; }
    // PCAP FIEL의 마지막 시간은 마지막 패킷의 시간정보
    entime = (long)pkthdr->ts.tv_sec;
    ether_type = ntohs(ep->ether_type);
    
    count++; // packet의 개수를 체크
    if (ether_type == ETHERTYPE_IP)
    {   
        iph = (struct ip *)packet;
        if (iph->ip_p == IPPROTO_TCP)
        {            
	    packet = packet + iph->ip_hl * 4;
	    tcph =(struct tcphdr *)packet;
    
        // 파싱한 정보들을 모두 string으로 바꾸어 더해줌
	    sa = inet_ntoa(iph->ip_src);
	    sp = to_string(ntohs(tcph->source)); 
	    da = inet_ntoa(iph->ip_dst);
	    dp = to_string(ntohs(tcph->dest));
	    type = to_string(iph->ip_p);
	    tmp = sa+","+sp+","+da+","+dp+","+type;
        } 
        else if (iph->ip_p == IPPROTO_UDP)
        {
	    packet = packet + iph->ip_hl * 4;
	    udph =(struct udphdr *)packet;	           

            sa = inet_ntoa(iph->ip_src);
            sp = to_string(ntohs(udph->source));
            da = inet_ntoa(iph->ip_dst);
            dp = to_string(ntohs(udph->dest));
            type = to_string(iph->ip_p);
            tmp = sa+","+sp+","+da+","+dp+","+type;
        }     
        else 
        {
            sa = inet_ntoa(iph->ip_src);
            sp = "none";
            da = inet_ntoa(iph->ip_dst);
            dp = "none";
            type = to_string(iph->ip_p);
            tmp = sa+","+sp+","+da+","+dp+","+type;
        }
    }   
    else
    {
	counteth++;
	sa = "none";
	sp = "none";
	da = "none";
	dp = "none";
	type = to_string(ether_type);
        tmp = sa+","+sp+","+da+","+dp+","+type;
    }
    // unordered set에 파싱한 string을 저장함
    pcap_set.insert(tmp);
}   