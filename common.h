#ifndef COMMON_H
#define COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32


#define SERVER_PK_PATH "d:/server.pk"
#define SERVER_SK_PATH "d:/server.sk"

#define CLIENT_PK_PATH "d:/client.pk"
#define CLIENT_SK_PATH "d:/client.sk"

#else
typedef int SOCKET;

#define closesocket close

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <unistd.h>
#include <errno.h>

#define SERVER_PK_PATH "/home/veins/server.pk"
#define SERVER_SK_PATH "/home/veins/server.sk"

#define CLIENT_PK_PATH "/home/veins/client.pk"
#define CLIENT_SK_PATH "/home/veins/client.sk"
#endif

#define ERRORMSG strerror(errno)

#define EVN EV << "\n"
#define EVN1(s1) EV << (s1) << "\n"
#define EVN2(s1, s2) EV << (s1) << (s2) << "\n"
#define EVN3(s1, s2, s3) EV << (s1) << (s2) << (s3) << "\n"
#define EVN4(s1, s2, s3, s4) EV << (s1) << (s2) << (s3) << (s4) << "\n"
#define EVN5(s1, s2, s3, s4, s5) EV << (s1) << (s2) << (s3) << (s4) << (s5) << "\n"

//char *stringhex(unsigned char *data, size_t len);
#define EVHEX(data, len) {char *__str = stringhex((unsigned char *)(data), (len)); EVN1(__str); free(__str);}

#define VFIN(errmsg) throw cRuntimeError((errmsg))
#define VERR(mainmsg) EVN3(mainmsg, " ", ERRORMSG); VFIN((mainmsg))


#define PRINTKEYINFO(key, len, des) printf("%s\n", (des)); printhex((key), (len)); printf("\n\n")


void read_key_from_path_and_print_info(const char* path, unsigned char* key_to, size_t len, const char* des, ...);


//ʹ��aes128(��ʼ����aes_iv����Կaes_key), ���ܳ���Ϊdata_len��data�����������out
//data���ȱ�����16�ı���������ɴ��뷽��֤
void aes_128_encrypt(const char *aes_key, char *aes_iv, char *data, size_t data_len, char *out);

//ʹ��aes128(��ʼ����aes_iv����Կaes_key), ���ܳ���Ϊdata_len��data�����������out
void aes_128_decrypt(const char *aes_key, char *aes_iv, char *data, size_t data_len, char *out);

//��sockfd��ȡn�ֽ����ݵ�buffer��
void read_nbytes_from_socket(int sockfd, char *buffer, size_t n);

//��sockfd��ȡָ�������ֽ����ݵ�buffer�У����ݰ�ǰ4���ֽ��������ܳ��ȣ�������ǰ8�ֽڣ�����5-8�ֽ���������ʵ���ȣ�ȥ��Ϊ�˲���16������������ֽڣ���ʣ���Ϊ���ܺ����ݳ���
//���ݰ���aes128���ܣ���ʼ����Ϊiv����ԿΪkey
 int read_from_socket_with_bytespefix_then_decrept(int sockfd, char *key, char *iv);

//�������һ������Ϊ16-256�ֽڵ����char�����������ݣ����Ȳ���16�ı����Ĳ�����0���
//���ݲ���16�ı�����ĳ��Ⱥ����ݵ���ʵ���Ȼ���Ϊ32λ���η���ǰ8�ֽ�
//������������ݻᱻaes128���ܣ���ʼ����Ϊiv����ԿΪkey
//��ʵ�����ݳ�����random_data_len���أ�����16������ĳ�����random_data_len_to16����
//����������data_plain���أ�����������data_encrypted����
void random_len_data_encrypt_aes128(int *random_data_len, //true random data len
                                    int *random_data_len_to16, // 16-256 , 16 multi
                                    const char *aes_key,
                                    const char *aes_iv,
                                    char **data_plain,
                                    char **data_encrypted);

//����k+k1+k2��sha256ֵ����out����
void sha256(const unsigned char *k, const unsigned char *k1, const unsigned char *k2, unsigned char *out);

#ifdef __cplusplus
}
#endif

#endif //COMMON_H
