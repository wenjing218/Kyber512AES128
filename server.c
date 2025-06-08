#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#include "api.h"

#include "randombytes.h"
#include "printhex.h"
#include "common.h"
#include "time.h"

unsigned char       pk[pqcrystals_kyber512_PUBLICKEYBYTES];
unsigned char       sk[pqcrystals_kyber512_SECRETKEYBYTES];

unsigned char       pk1[pqcrystals_kyber512_PUBLICKEYBYTES];
unsigned char       sk1[pqcrystals_kyber512_SECRETKEYBYTES];

unsigned char       pk2[pqcrystals_kyber512_PUBLICKEYBYTES];
unsigned char       sk2[pqcrystals_kyber512_SECRETKEYBYTES];

unsigned char 	    k[pqcrystals_kyber512_ref_BYTES];
unsigned char       c[pqcrystals_kyber512_CIPHERTEXTBYTES];

unsigned char 	    k1[pqcrystals_kyber512_ref_BYTES];
unsigned char       c1[pqcrystals_kyber512_CIPHERTEXTBYTES];

unsigned char 	    k2[pqcrystals_kyber512_ref_BYTES];
unsigned char       c2[pqcrystals_kyber512_CIPHERTEXTBYTES];

int                 ret_val;

//��console���server��pk��sk��Ϣ
int print_key(){
    FILE *fp = fopen(SERVER_PK_PATH, "rb");
    fread(pk, pqcrystals_kyber512_PUBLICKEYBYTES, 1, fp);
    fclose(fp);

    fp = fopen(SERVER_SK_PATH, "rb");
    fread(sk, pqcrystals_kyber512_SECRETKEYBYTES, 1, fp);
    fclose(fp);

    printf("Server Public Key:\n");
    printhex(pk, pqcrystals_kyber512_PUBLICKEYBYTES);

    printf("\nServer Secret Key:\n");
    printhex(sk, pqcrystals_kyber512_SECRETKEYBYTES);

	printf("\n");

    return 0;
}

//����server�����pk��sk��Կ��
int generate_key(){
    if ( (ret_val = pqcrystals_kyber512_ref_keypair(pk, sk)) != 0) {
        printf("generatekey failed! returned <%d>\n", ret_val);
        return 1;
    }

	FILE *fp = fopen(SERVER_PK_PATH, "wb");
    fwrite(pk, pqcrystals_kyber512_PUBLICKEYBYTES, 1, fp);
    fclose(fp);

    fp = fopen(SERVER_SK_PATH, "wb");
    fwrite(sk, pqcrystals_kyber512_SECRETKEYBYTES, 1, fp);
    fclose(fp);

    print_key();

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc == 2) {
        if (strcmp(argv[1], "generatekey") == 0) {
            return generate_key();
        }

        if (strcmp(argv[1], "printkey") == 0) {
            return print_key();
        }
    }

#ifdef _WIN32
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		printf("WSAStartup failed!");
		return -1;
	}
#endif

	//��ȡserver��sk
	read_key_from_path_and_print_info(SERVER_SK_PATH, sk2, pqcrystals_kyber512_ref_SECRETKEYBYTES, "Read server secret key from %s as sk2 successfully!\n", SERVER_SK_PATH);

	//��ȡclient��pk
	read_key_from_path_and_print_info(CLIENT_PK_PATH, pk1, pqcrystals_kyber512_ref_PUBLICKEYBYTES, "Read client public key from %s as pk1 successfully!\n", CLIENT_PK_PATH);

	//��ʼ��60666�˿ڼ���
	SOCKET server_fd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Create socket failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(60666);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed!");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

	printf("Server Bind 60666 successfully!\n\n");

	while (1) {
		SOCKET new_socket;
		printf("Ready for accept connection!\n\n");
		if ((new_socket = accept(server_fd, (struct sockaddr *)&address, &addrlen)) < 0) {
        	perror("accept");
        	exit(EXIT_FAILURE);
    	}

		printf("Accept new client connection!\n");

		//��ʼ����������

		//��client������pk��c2
		read_nbytes_from_socket(new_socket, pk, pqcrystals_kyber512_PUBLICKEYBYTES);
    	read_nbytes_from_socket(new_socket, c2, pqcrystals_kyber512_CIPHERTEXTBYTES);

		printf("Received pk, c2 from client\n");
		PRINTKEYINFO(pk, pqcrystals_kyber512_PUBLICKEYBYTES, "Received pk is:");
		PRINTKEYINFO(c2, pqcrystals_kyber512_CIPHERTEXTBYTES, "Received c2 is:");

		//��c2���Լ���˽Կsk2decaps��k2
		if ( (ret_val = pqcrystals_kyber512_ref_dec(k2, c2, sk2)) != 0) {
     	    printf("Error key c2: ret value is %d\n", ret_val);
			continue;
   	 	}

		printf("Decaps k2 from sk2 c2:\n");
		PRINTKEYINFO(k2, pqcrystals_kyber512_ref_BYTES, "k2 is:");

		//�øս��յ���pk encaps��c��k
		if ( (ret_val = pqcrystals_kyber512_ref_enc(c, k, pk)) != 0) {
        	printf("crypto_kem_enc failed <%d>\n", ret_val);
        	continue;
    	}

		printf("Encaps pk ---> c k successully!\n");
		PRINTKEYINFO(k, pqcrystals_kyber512_ref_BYTES, "k is:");

		//��Ԥ����client��pk1 encaps��c1��k1
		if ( (ret_val = pqcrystals_kyber512_ref_enc(c1, k1, pk1)) != 0) {
        	printf("crypto_kem_enc failed <%d>\n", ret_val);
        	continue;
    	}

		printf("Encaps pk1 ---> c1 k1 successully!\n");
		PRINTKEYINFO(k1, pqcrystals_kyber512_ref_BYTES, "k1 is:");
		PRINTKEYINFO(c1, pqcrystals_kyber512_CIPHERTEXTBYTES, "c1 is:");
		PRINTKEYINFO(c, pqcrystals_kyber512_CIPHERTEXTBYTES, "c is:");

		//��c��c1���͸�client
		send(new_socket, c, pqcrystals_kyber512_CIPHERTEXTBYTES, 0);
		send(new_socket, c1, pqcrystals_kyber512_CIPHERTEXTBYTES, 0);

		printf("Send c c1 to client successfully!\n");

		unsigned char aes_iv[32];

		//��k��k1��k2����sha3-256���õ�AES��key��iv
		sha256(k, k1, k2, aes_iv);
		printf("Hash k k1 k2 by sha3-256, get aes key and iv:\n");
		printf("AES KEY:\n");
		printhex(aes_iv, 16);
		printf("\n");
		printf("AES IV:\n");
		printhex(aes_iv+16, 16);
		printf("\n");

		unsigned char iv_encrypt[16], iv_decrypt[16];
		memcpy(iv_encrypt, aes_iv + 16, 16);
		memcpy(iv_decrypt, aes_iv + 16, 16);

		int nround = 0;

		while (1) {
			//��client�������ݣ����������
			printf("\n\nRound %d", ++nround);

			int datalen = read_from_socket_with_bytespefix_then_decrept(new_socket, aes_iv, iv_decrypt);

			if (datalen == 0) {
				printf("received client close signal!\n");
				nround = 0;
				break;
			}

			int random_data_len; //true random data len
			int random_data_len_to16; // 16-256 , 16 multi

			char* random_data_plain;
			char* random_data_encryped_lenprefix;

			char *temp_iv_str = stringhex(iv_encrypt, 16);

			//����һ��������16-256֮���������ݣ�����aes���ܣ������ݵ���ʵ���ȺͲ���16�����ĳ��ȼ������ݿ��ǰ�棨����int���ͣ��������߹�ռ��8�ֽڣ��������͸�client
			random_len_data_encrypt_aes128(&random_data_len, &random_data_len_to16, aes_iv, iv_encrypt,
				&random_data_plain, &random_data_encryped_lenprefix);


			printf("\n\nSent random data len(%d to %d)\nencrypt by iv: %s\n\n", random_data_len, random_data_len_to16, temp_iv_str);
			free(temp_iv_str);

			PRINTKEYINFO(random_data_encryped_lenprefix + 8, random_data_len_to16, "Encrypted cipher data:");
			PRINTKEYINFO(random_data_plain, random_data_len, "Plain data:");

			send(new_socket, random_data_encryped_lenprefix, 8 + random_data_len_to16, 0);

			free(random_data_plain);
			free(random_data_encryped_lenprefix);
		}

		printf("\n\n\nclose socket\n");

		closesocket(new_socket);
	}

    closesocket(server_fd);

#ifdef _WIN32
	WSACleanup();
#endif

    return 0;
}

//cc server.c printhex.c -o server -lpqmagic_kyber_std -lpthread -lcrypto
