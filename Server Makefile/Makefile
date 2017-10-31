Secure_FW_Update_Server: Secure_FW_Update_Server.o
	gcc -o Secure_FW_Update_Server Secure_FW_Update_Server.o -lcrypto -lssl
Secure_FW_Update_Server.o: Secure_FW_Update_Server.c
	gcc -c Secure_FW_Update_Server.c

clean:
	rm -f Secure_FW_Update_Server Secure_FW_Update_Server.o
