#ifndef PRINTHEX_H
#define PRINTHEX_H

#ifdef __cplusplus
extern "C" {
#endif

//��16���ƴ�ӡ����
void printhex(unsigned char *data, size_t len);

//����16������ʽ���ַ���
char *stringhex(unsigned char *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif //PRINTHEX_H
