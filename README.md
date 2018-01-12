# SecurePi_Secure-FW-update

클라이언트 측(Secure Pi)
1. root계정 로그인
2. 디렉토리 생성 및 이동
	- mkdir /root/securepi (이미 존재한다면 생략)
	- cd /root/securepi
3. Secure Firmware Update 파일 다운
	- git clone https://github.com/khu-mesl-348/SecurePi_Secure-FW-update.git
4. Client 설정
	- cd /root/securepi/SecurePi_Secure-FW-update/FW_Client
	- make
	- ./Secure_FW_Update_Client

서버 측(Linux)
1. 계정 로그인
2. 디렉토리 생성 및 이동
	- mkdir $(사용자 홈 디렉토리)/securepi (이미 존재한다면 생략)
	- cd $(사용자 홈 디렉토리)/securepi
3. Secure Firmware Update 파일 다운
	- git clone https://github.com/khu-mesl-348/SecurePi_Secure-FW-update.git
4. Server 설정
	- cd /root/securepi/SecurePi_Secure-FW-update/FW_Server
	- make
	- ./Secure_FW_Update_Server
