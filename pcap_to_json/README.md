# pcap_to_json

### pcap 파일에서 각 패킷의 정보 추출 후 elasticsearch에 올립니다.
### 패킷의 5가지 정보 → type, source ip, destination ip, port, protocol type + time
-----------------
1-1) 속도 측정을 위해 237M의 Pcap 파일을 생성합니다.

 → 총 45만개(452396개)의 패킷

#### python dpkt library 사용
 
2-1) final.py → python dpkt library를 사용하여 정보들을 파싱합니다.

2-2) json파일로 dump합니다.

2-3) elasticsearch라이브러리를 사용하여 elastic서버에 올립니다.

#### c언어 libpcap library 사용

3-1) pcaptojson.c → c언어 libpcap library를 사용하여 정보들을 파싱합니다.

3-2) elasticsearch json file 형식에 맞춰서 json파일로 저장

 → 파싱한 후 파일입출력(fopen, fscanf)을 사용하여 바로 파일에 쓸 수 있도록 코드를 작성하였습니다.
 
3-3) 쉘 스크립트를 사용하여 백그라운드에서 병렬로 elasticsearch서버에 올립니다.

#### 속도 측정

+ 파싱 후 json파일을 만드는데 소요 시간 → python: 10sec, C: 0.6sec
+ Json file을 elasticsearch서버에 올리는데 소요 시간 → python:65sec, C: 41sec
+ C언어 libpcap library가 훨씬 빠른 속도를 보여줍니다.


+ 병렬 실행을 사용하여 10M pcap file 25개(250M, 약124만개)를 json file 25개(165.7M)로 변환 → 0.4sec 소요
+ 병렬 실행을 사용하여 json file을 elastic search에 insert → 11sec 소요

#### 패킷의 중복 제거
4-1) jsonhash.cpp → unordered set을 사용하여 패킷들의 중복 제거 후 json으로 변환합니다.
