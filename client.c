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


//向console输出client的pk和sk信息
int print_key(){
    FILE *fp = fopen(CLIENT_PK_PATH, "rb");
    fread(pk, pqcrystals_kyber512_PUBLICKEYBYTES, 1, fp);
    fclose(fp);

    fp = fopen(CLIENT_SK_PATH, "rb");
    fread(sk, pqcrystals_kyber512_SECRETKEYBYTES, 1, fp);
    fclose(fp);

    printf("Client Public Key:\n");
    printhex(pk, pqcrystals_kyber512_PUBLICKEYBYTES);

    printf("\nClient Secret Key:\n");
    printhex(sk, pqcrystals_kyber512_SECRETKEYBYTES);

	printf("\n");

    return 0;
}

//生成client自身的pk和sk密钥对
int generate_key(){
    if ( (ret_val = pqcrystals_kyber512_ref_keypair(pk, sk)) != 0) {
        printf("generatekey failed! returned <%d>\n", ret_val);
        return 1;
    }

	FILE *fp = fopen(CLIENT_PK_PATH, "wb");
    fwrite(pk, pqcrystals_kyber512_PUBLICKEYBYTES, 1, fp);
    fclose(fp);

    fp = fopen(CLIENT_SK_PATH, "wb");
    fwrite(sk, pqcrystals_kyber512_SECRETKEYBYTES, 1, fp);
    fclose(fp);

    print_key();

    return 0;
}

#ifdef _WIN32
int testspeed(const char *s){
   
	int n = atoi(s);

    if (n == 0) {
        printf("test speed count invalid or less than 0 o", s);
        return -1;
	}

    uint8_t *pk = malloc(pqcrystals_kyber512_PUBLICKEYBYTES * n);
    uint8_t *sk = malloc(pqcrystals_kyber512_SECRETKEYBYTES * n);
    uint8_t *ss = malloc(32 * n);
    uint8_t *ct = malloc(pqcrystals_kyber512_CIPHERTEXTBYTES * n);

    for (int i = 0; i < n; i++) {
        ret_val = pqcrystals_kyber512_ref_keypair(pk + i* pqcrystals_kyber512_PUBLICKEYBYTES, sk + i * pqcrystals_kyber512_SECRETKEYBYTES);
        if (ret_val != 0) {
            printf("Keypair generation failed: %d\n", ret_val);
            return -1;
        }
    }

    int ret_val = 0;
    LARGE_INTEGER start, end, tc;
	QueryPerformanceFrequency(&tc);
        
	uint8_t pktemp[pqcrystals_kyber512_PUBLICKEYBYTES];
    uint8_t sktemp[pqcrystals_kyber512_SECRETKEYBYTES];

	QueryPerformanceCounter(&start);

    for (int i = 0; i < n; i++) {
        ret_val = pqcrystals_kyber512_ref_keypair(pktemp, sktemp);
        if (ret_val != 0) {
            printf("Keypair generation failed: %d\n", ret_val);
            return -1;
        }
    }

    QueryPerformanceCounter(&end);

	double keypair_timeused = ((double)(end.QuadPart - start.QuadPart) * 1000) / tc.QuadPart;

    QueryPerformanceCounter(&start);

    for (int i = 0; i < n; i++) {
        ret_val = pqcrystals_kyber512_ref_enc(ct + pqcrystals_kyber512_CIPHERTEXTBYTES * i, ss + 32 * i, pk+ pqcrystals_kyber512_PUBLICKEYBYTES * i);
        if (ret_val != 0) {
            printf("Enc failed: %d\n", ret_val);
            return -1;
        }
    }

    QueryPerformanceCounter(&end);

    double keyenc_timeused = ((double)(end.QuadPart - start.QuadPart) * 1000) / tc.QuadPart;

    QueryPerformanceCounter(&start);

    for (int i = 0; i < n; i++) {
        ret_val = pqcrystals_kyber512_ref_dec(ss + 32 * i, ct + pqcrystals_kyber512_CIPHERTEXTBYTES * i, sk + pqcrystals_kyber512_SECRETKEYBYTES*i);
        if (ret_val != 0) {
            printf("Dec failed: %d\n", ret_val);
            return -1;
        }
    }

    QueryPerformanceCounter(&end);

    double keydec_timeused = ((double)(end.QuadPart - start.QuadPart) * 1000) / tc.QuadPart;

	printf("Key pair %d times: %f ms, avg:  %f ms\n",n, keypair_timeused, keypair_timeused/n);
    printf("Key enc  %d times: %f ms, avg:  %f ms\n", n,keyenc_timeused, keyenc_timeused /n);
    printf("Key dec  %d times: %f ms, avg:  %f ms\n", n, keydec_timeused, keydec_timeused /n);


	free(pk);
	free(sk);
	free(ss);
	free(ct);

    return 0;
}
#endif

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
    else if (argc == 3) {
        if (strcmp(argv[1], "testspeed") == 0) {
            return testspeed(argv[2]);
        }
	}

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        return -1;
    }
#endif

    //读取server的公钥
    read_key_from_path_and_print_info(SERVER_PK_PATH, pk2, pqcrystals_kyber512_PUBLICKEYBYTES, "Read server public key from %s as pk2 successfully!\n", SERVER_PK_PATH);

	//读取client的私钥
    read_key_from_path_and_print_info(CLIENT_SK_PATH, sk1, pqcrystals_kyber512_SECRETKEYBYTES, "Read client secret key from %s as sk1 successfully!\n", CLIENT_SK_PATH);

	//生成临时的pk和sk密钥对
	if ( (ret_val = pqcrystals_kyber512_ref_keypair(pk, sk)) != 0) {
        printf("Generate pk,sk failed! returned <%d>\n", ret_val);
        return 1;
    }

	printf("\nGenerate pk,sk key pair from Kyber KeyGen successfully!\n\n");
    PRINTKEYINFO(pk, pqcrystals_kyber512_PUBLICKEYBYTES, "Temp public key is:");
    PRINTKEYINFO(sk, pqcrystals_kyber512_SECRETKEYBYTES, "Temp secret key is:");

	//encaps预留的server的pk，得到c2和k2
	if ( (ret_val = pqcrystals_kyber512_ref_enc(c2, k2, pk2)) != 0) {
        printf("crypto_kem_enc failed <%d>\n", ret_val);
        return 1;
    }

	printf("Encaps pk2 ---> c2 k2 successully!\n");
    PRINTKEYINFO(k2, pqcrystals_kyber512_ref_BYTES, "K2 is:");
    PRINTKEYINFO(c2, pqcrystals_kyber512_CIPHERTEXTBYTES, "c2 is:");


	//通过socket连接server
    SOCKET sock = 0;
    struct sockaddr_in serv_addr;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(60666);

    if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }

	printf("Connect to 127.0.0.1:60666 successfully!\n\n");

	//将发送pk和c2到server
    send(sock, pk, pqcrystals_kyber512_PUBLICKEYBYTES, 0);
    send(sock, c2, pqcrystals_kyber512_CIPHERTEXTBYTES, 0);

	printf("Send pk c2 to server successfully!\n\n");

	//接收server发送的c和c1
	read_nbytes_from_socket(sock, c, pqcrystals_kyber512_CIPHERTEXTBYTES);
    read_nbytes_from_socket(sock, c1, pqcrystals_kyber512_CIPHERTEXTBYTES);

	printf("Received c, c1 from server successfully!\n");

    PRINTKEYINFO(c, pqcrystals_kyber512_CIPHERTEXTBYTES, "c is:");
    PRINTKEYINFO(c1, pqcrystals_kyber512_CIPHERTEXTBYTES, "c1 is:");

    //将刚接收到的c，通过自己的私钥decaps出k
	if ( (ret_val = pqcrystals_kyber512_ref_dec(k, c, sk)) != 0) {
     	printf("Error key c: ret value is %d\n", ret_val);
		return -1;
   	}

	printf("Decaps k from sk c:\n");
    PRINTKEYINFO(k, pqcrystals_kyber512_ref_BYTES, "k is:");

    //将刚接收到的c1，通过临时生成的的私钥decaps出k1
	if ( (ret_val = pqcrystals_kyber512_ref_dec(k1, c1, sk1)) != 0) {
     	printf("Error key c1: ret value is %d\n", ret_val);
		return -1;
   	}

	printf("Decaps k1 from sk1 c1:\n");
    PRINTKEYINFO(k1, pqcrystals_kyber512_ref_BYTES, "k1 is:");

	unsigned char aes_iv[32];

	//对k，k1，k2进行sha3-256，得到AES的key和iv
	sha256(k, k1, k2, aes_iv);
	printf("Hash k k1 k2 by sha3-256, get aes key and iv:\n");
	printf("AES KEY:\n");
	printhex(aes_iv, 16);
	printf("\n");
	printf("AES IV:\n");
	printhex(aes_iv+16, 16);
	printf("\n\n");

    unsigned char iv_encrypt[16], iv_decrypt[16];
    memcpy(iv_encrypt, aes_iv + 16, 16);
    memcpy(iv_decrypt, aes_iv + 16, 16);

    int ncount = 5;
    int nround = 0;

    while (ncount--)
    {
        printf("\n\nRound %d\n\n", ++nround);

        //生成一个长度在16-256之间的随机数据，并用aes加密，该数据的真实长度和补齐16倍数的长度加在数据块的前面（都是int类型，所在两者共占用8字节），并发送给server
        int random_data_len;
        int random_data_len_to16;

        char* random_data_plain;
        char* random_data_encryped_lenprefix;

        char* temp_iv_str = stringhex(iv_encrypt, 16);

        random_len_data_encrypt_aes128(&random_data_len, &random_data_len_to16, aes_iv, iv_encrypt,
            &random_data_plain, &random_data_encryped_lenprefix);

        printf("Sent random data len(%d to %d)\nencrypt by iv: %s\n\n", random_data_len, random_data_len_to16, temp_iv_str);
        free(temp_iv_str);
        PRINTKEYINFO(random_data_encryped_lenprefix + 8, random_data_len_to16, "Encrypted cipher data:");
        PRINTKEYINFO(random_data_plain, random_data_len, "Plain data:");

        send(sock, random_data_encryped_lenprefix, 8 + random_data_len_to16, 0);

        free(random_data_plain);
        free(random_data_encryped_lenprefix);


        //从server接收数据，并解密输出
        read_from_socket_with_bytespefix_then_decrept(sock, aes_iv, iv_decrypt);
    }

    char endstr[4] = { 0 };
    send(sock, endstr, 4, 0);

    printf("\n\n\nclose socket\n");
    closesocket(sock);

#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}

//cc client.c printhex.c randombytes.c common.c -o client -lpqmagic_kyber_std -lcrypto
