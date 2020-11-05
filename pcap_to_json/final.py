import dpkt
import socket
import datetime
import json
import time
from elasticsearch import Elasticsearch
from elasticsearch import helpers

jsonlist = [] # json 형식으로 저장하기 위해 리스트를 생성합니다.

# For each packet in the pcap process the contents
def printPcap(pcap): # PCAP FILE의 패킷들을 파싱하는 함수입니다.4
    
    index_name = 'tetspcap250' # es index name을 설정해 줍니다.
    for timestamp, buf in pcap: # PCAP FILE 안의 패킷들을 하나하나 돌며 파싱합니다.
        # Unpack the Ethernet frame
        eth = dpkt.ethernet.Ethernet(buf) # 패킷의 이더넷 정보입니다.

        # Make sure the Ethernet frame contains an IP packet
        if not isinstance(eth.data, dpkt.ip.IP): # 만약 IP타입의 이더넷이 아닐경우(IP가 존재하지 않습니다.)
            form = {'_index' : index_name,
                    '_source': {'Time' : str(datetime.datetime.utcfromtimestamp(timestamp)), # 시간정보
                    'Type' : eth.data.__class__.__name__, # 이더넷 타입
                    'Path' : 'path' # 경로(여기서는 예시)
                    }} # es에 JSON으로 올리기 위한 양식입니다.
            jsonlist.append(form) # 미리 만들어 두었던 리스트에 넣습니다.
            continue
        
        # grab the data within the Ethernet frame (the IP packet)
        ip = eth.data # IP 패킷의 데이타입니다.

        # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
        do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
        more_fragments = bool(ip.off & dpkt.ip.IP_MF)
        fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

        # Check for TCP
        if ip.get_proto(ip.p).__name__ == 'TCP':
            form = {'_index' : index_name,
                    '_source': {'Time' : str(datetime.datetime.utcfromtimestamp(timestamp)),
                    'ProtocolType' : ip.get_proto(ip.p).__name__,
                    'SourceIp' : socket.inet_ntoa(ip.src),
                    'DestinationIp' : socket.inet_ntoa(ip.src),
                    'SourcePort' : ip.data.sport,
                    'DestinationPort' : ip.data.dport ,
                    'Path' : 'path'
                    }}
            jsonlist.append(form)
            continue

        # Check for UDP
        if ip.get_proto(ip.p).__name__ == 'UDP':
            form = {'_index' : index_name,
                    '_source': {'Time' : str(datetime.datetime.utcfromtimestamp(timestamp)),
                    'ProtocolType' : ip.get_proto(ip.p).__name__,
                    'SourceIp' : socket.inet_ntoa(ip.src),
                    'DestinationIp' : socket.inet_ntoa(ip.src),
                    'SourcePort' : ip.data.sport,
                    'DestinationPort' : ip.data.dport,
                    'Path' : 'path'
                    }}
            jsonlist.append(form)
            continue

        # else IP ethernet
        form = {'_index' : index_name,
                '_source': {'Time' : str(datetime.datetime.utcfromtimestamp(timestamp)),
                'ProtocolType' : ip.get_proto(ip.p).__name__,
                'SourceIp' : socket.inet_ntoa(ip.src),
                'DestinationIp' : socket.inet_ntoa(ip.src),
                'Path' : 'path'
                }}
        jsonlist.append(form)


def main():
    start_time = time.time() # 시작시간을 저장합니다.
    f = open('./test250.pcap') # 사용할 피캡파일입니다.
	open_time = time.time() # 파일 open 시간 계산을 위한 시간 저장입니다.
	print 'openfile time {}'.format(open_time - start_time) # 파일 open 시간입니다.
    pcap = dpkt.pcap.Reader(f) # 피캡파일을 읽습니다.
    printPcap(pcap) # 피캡파일을 읽는 함수를 실행시킵니다.
    json_time = time.time() # json으로 변환하는데 걸리는 시간 계산을 위한 시간 저장입니다.
    print 'json time {}'.format(json_time - open_time) # json으로 변환하는데 걸리는 시간입니다.
    print len(jsonlist) # 패킷의 개수 입니다.
    
    es = Elasticsearch('http://localhost:9200/') # es 서버와 연결합니다.
    helpers.bulk(es, jsonlist) # es에 bulk api를 사용하여 업로드 합니다.
	print 'end time {}'.format(time.time() - json_time) # es에 업로드 하는데 걸리는 시간입니다.

if __name__ == '__main__':
        main()

