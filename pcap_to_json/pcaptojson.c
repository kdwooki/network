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
#define _CRT_SECURE_NO_WARNINGS

struct ip *iph; // ip header 저장
char *path; // pcap file 경로 저장
struct tcphdr *tcph; // tcp header 저장
struct udphdr *udph; // udp header 저장
char *indexname; // es indexname 저장
FILE *fp; // json변환 후 저장할 json 파일

// 피캡 파일 안의 패킷을 돌며 파싱하는 함수
void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet);

int main(int argc, char *argv[])
{
    clock_t start = clock(); // start time
    char errbuf[PCAP_ERRBUF_SIZE]; // error 선언 (이 부분은 잘 모르겠습니다.)
    pcap_t *pcd; // 피캡 파일 선언
    char *pfname = argv[1]; // argument1 PCAP FILE name
    path = argv[1]; // PCAP FIEL name = path
    indexname = argv[2]; // es indexname
    char *jfname = argv[3]; // 저장할 json file name
    pcd = pcap_open_offline(pfname, errbuf); // PCAP FILE 열기
    fp = fopen(jfname, "w"); // 저장할 json file open
    if (pcd == NULL) // error.. 
    {
        printf("%s\n", errbuf);
        exit(1);
    }
    pcap_loop(pcd, 0, callback, NULL); // 함수 실행
    clock_t end = clock(); // end time
    fclose(fp);
    printf("Time: %lf\n", (double)(end -start)/CLOCKS_PER_SEC); // duration time
    return 0;
}

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{   
    fprintf(fp, "{\"index\":{\"_index\":\"%s\"}}\n",indexname); // es index name 설정
    struct ether_header *ep; // ethernet header 설정
    unsigned short ether_type; // ethernet type
    int length=pkthdr->len; // packet 하나의 길이
    ep = (struct ether_header *)packet; // packet의 ehernet header
    packet += sizeof(struct ether_header); // 패킷을 읽으면서(이동하면서) header들을 지정해 주는 것 같습니다.
    
    ether_type = ntohs(ep->ether_type); // ethernet type
    if (ether_type == ETHERTYPE_IP) // ethernet type이 IP 일 경우
    {   
        iph = (struct ip *)packet; // IP header
        fprintf(fp, "{\"time\":\"%08d\",", pkthdr->ts.tv_sec);
        fprintf(fp, "\"path\":\"%s\",", path);
	    fprintf(fp, "\"protocol_type_number\":\"%X\",", iph->ip_p);
        fprintf(fp, "\"Src_Address\":\"%s\",", inet_ntoa(iph->ip_src));
        fprintf(fp, "\"Dst_Address\":\"%s\"", inet_ntoa(iph->ip_dst)); 
        if (iph->ip_p == IPPROTO_TCP) // IP중 protocol type이 TCP인 경우
        {
	        packet = packet + iph->ip_hl * 4;
	        tcph =(struct tcphdr *)packet; // TCP header	

            fprintf(fp, ",\"Src_Port\":\"%d\"," , ntohs(tcph->source));
            fprintf(fp, "\"Dst_Port\":\"%d\"}\n" , ntohs(tcph->dest));
        } 
        else if (iph->ip_p == IPPROTO_UDP) // IP중 protocol type이 UDP인 경우
        {
	        packet = packet + iph->ip_hl * 4;
	        udph =(struct udphdr *)packet; // UDP header
            
	        fprintf(fp, ",\"Src_Port\":\"%d\"," , ntohs(udph->source));
            fprintf(fp, "\"Dst_Port\":\"%d\"}\n" , ntohs(udph->dest));
        }     
        else 
        {
            fprintf(fp, "}\n");                       
        }
    }   
    else // ethernet type이 IP가 아닌경우
    {
        fprintf(fp, "{\"time\":\"%08d\",", pkthdr->ts.tv_sec);
        fprintf(fp, "\"path\":\"%s\",", path);
	    fprintf(fp, "\"ethernet_type_number\":\"%X\"}\n", ether_type);
    }  
}   