
//Nilay Altun 

#include<stdio.h>
#include"openssl/blowfish.h"
#include<stdlib.h>
#include<string.h>
#define SIZE 8

BF_KEY *key = (BF_KEY *)calloc(1, sizeof(BF_KEY));

void *fs_encrypt(void *plaintext, int bufsize, char *keystr,int *resultlen){
    unsigned char *out = (unsigned char *)calloc(100, sizeof(char));
    int a;
    char ivec[8];
    for(a=0; a<8; a++) ivec[a] = 'i';
    BF_set_key(key, SIZE, (const unsigned char *)keystr);
    BF_cbc_encrypt((const unsigned char*)plaintext, out,bufsize, key, (unsigned char*)ivec, BF_ENCRYPT);
    *resultlen=strlen((const char *)out);
    return (void *) out;
}

void *fs_decrypt(void *ciphertext, int bufsize, char *keystr,int *resultlen){
    
    unsigned char *out2 = (unsigned char *)calloc(100, sizeof(char));
    int a;
    char ivec[8];
    for(a=0; a<8; a++) ivec[a] = 'i';
    BF_cbc_encrypt((const unsigned char*)ciphertext, out2,bufsize, key, (unsigned char*)ivec, BF_DECRYPT);
    *resultlen=strlen((const char*) out2)+1;
    return (void *) out2;
}