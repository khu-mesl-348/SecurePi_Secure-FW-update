Secure_FW_Update_Client: Secure_FW_Update_Client.o
	gcc -o Secure_FW_Update_Client Secure_FW_Update_Client.o -ltspi -lcrypto -lssl
Secure_FW_Update_Client.o: Secure_FW_Update_Client.c
	gcc -c Secure_FW_Update_Client.c

clean:
	rm -f Secure_FW_Update_Client Secure_FW_Update_Client.o
