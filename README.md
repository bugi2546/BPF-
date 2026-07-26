# BPFdoor 기반 이상행위 탐지 및 로그 수집 시스템 개발

## 프로젝트 개요
* **기간:** 2025.09 ~ 2025.12
* **팀 구성:** 3인 팀구성 프로젝트
* **한 줄 소개:** eBPF/BPF 기반 은닉 백도어의 동작 메커니즘 분석, 공격–피해 모의 시나리오 재현 및 Raw Socket·Reverse Shell 연계 행위 기반 실시간 탐지/JSON 로깅 시스템 구축
* **담당 역할:** BPFdoor 모의 공격 구현

## 사용 기술 및 환경
* **Environment / OS:** Linux (Ubuntu 22.04 LTS, Kali Linux), VMware, VS Code
* **Language / Framework:** Python 
* **Network & Analysis Tool:** Netcat, Raw Socket, Scapy, Linux CLI 

## 핵심 기능 및 구조
[Magic Packet 전송 (Scapy)] ➔ [Raw Socket 감지 & Reverse Shell 실행 (BPFdoor Mock)] ➔ [실시간 프로세스/소켓 연계 탐지 (Detector)] ➔ [JSON 로그 수집]

공격 수행(attacker.py) ➔ 위협 동작(bpfdoor_mock.py) ➔ 실시간 행위 탐지 및 대응(bpfdoor_detector.py)

* **BPFdoor 모의 악성코드 구현:** AF_PACKET / SOCK_RAW 기반 Raw Socket 바인딩 및 매직 키워드 수신 시 공격자로 Reverse Shell 연결 수행
* **공격자 스크립트 및 세션 수립:** Scapy 활용 매직 패킷 송신 및 Netcat 리스너를 통한 공격 세션 수립 재현
* **행위 기반 탐지 엔진 구현:** psutil 기반 Raw Socket 사용 프로세스 추적 및 외부 IP/Port 연결 행위를 연계한 실시간 탐지 
* **표준 보안 로그 자동 구조화:** 메타데이터를 포함한 JSON 포맷 파일 로깅 파이프라인 구축 

## 해결 과정
* **문제 상황:** 가상 환경 모의 실험 중 정상 프로세스가 사용 중인 Raw Socket과 악성코드의 Raw Socket이 혼재되어 오탐 발생 및 탐지 시점 지연 현상 발생
* **원인 분석:** 단순 소켓 존재 여부만 검사할 경우 시스템 정상 데몬까지 감지되며, Raw Socket을 오픈한 프로세스가 실제 Reverse Shell을 형성하기까지의 상태 변화를 단일 룰로 판단하기 어려움
* **해결 방법:** 탐지 조건을 단일 행위가 아닌 Raw Socket 보유 + 비정상 외부 세션 형성의 연계 조건으로 정교화하고, 프로세스 ID 단위 추적 알고리즘 적용
* **결과:** 정상 시스템 데몬과의 구별에 성공하여 오탐률을 획기적으로 낮추었으며, BPFdoor 동작 전체 흐름을 완벽히 실시간 감지하여 검증 완료

## 성과
1. **End-to-End 공격 및 방어 파이프라인 경험** 
2. **행위 기반 보안 관제 역량 체득** 
3. **SIEM 연동 가능한 로그 표준화 성공**

## 파일 구조
```text
├── README.md               # 프로젝트 상세 설명 및 실행 보고서
├── attacker.py             # Scapy 기반 매직 패킷 생성 및 전송 공격 스크립트
├── bpfdoor_mock.py         # Raw Socket 리스닝 및 Reverse Shell 동작 모의 악성코드
├── bpfdoor_detector.py     # Raw Socket, 프로세스 위장, Reverse Shell 연계 탐지 및 JSON 로깅 엔진

이 코드들은 실제 악성코드가 아니라 연구 및 학습 목적으로 제작된 모의 스크립트입니다.
