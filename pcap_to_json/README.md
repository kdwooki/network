# pcap_to_json

### 1. pcap 파일에서 각 패킷의 정보 추출하기
### → time, source ip, destination ip, port, protocol type
### 2. json파일로 저장하기
### 3. elasticsearch에 올리기
-----------------
1-1) 속도 측정을 위해 237M의 Pcap 파일을 생성합니다.
 → 총 45만개(452396개)의 패킷
 
2-1) final.py → 파이썬 dpkt 라이브러리를 사용하여 정보들을 파싱합니다.

2-2) json파일로 dump합니다.

2-3) elasticsearch라이브러리를 사용하여 elastic서버에 올립니다.

3-1) pcaptojson.c → c언어 libpcap 라이브러리를 사용하여 정보들을 파싱합니다.

3-2) elasticsearch json file 형식에 맞춰서 json파일로 저장
 → 파싱한 후 파일입출력(fopen, fscanf)을 사용하여 바로 파일에 쓸 수 있도록 코드를 작성하였습니다.
 
3-3) 쉘 스크립트를 사용하여 백그라운드 사용으로 elasticsearch서버에 올립니다.

4-1) jsonhash.cpp → unordered set을 사용하여 패킷들의 중복 제거 후 json으로 변환합니다.
