
//Nilay Altun 

#include<stdio.h>
#include"openssl/blowfish.h"
#include<stdlib.h>
#include<string.h>
#define SIZE 8

BF_KEY *key = (BF_KEY *)calloc(1, sizeof(BF_KEY));

void *fs_encrypt(void *plaintext, int bufsize, char *keystr,int *resultlen){

// Random initial vector declaration
	int a;    
    char ivec[8];
    for(a=0; a<8; a++) ivec[a] = 'i';

	unsigned char *out = (unsigned char *)calloc(1000, sizeof(char)); // out= ciphertext
	unsigned char *ptr_cipher = out;  // pointer to ciphertext
	unsigned char * ptr_text=(unsigned char *) plaintext;  //pointer to plain text
	unsigned char P[bufsize]; //blocks

    BF_set_key(key, SIZE, (const unsigned char*)keystr ); //set key
	    
// XOR with initial vector
    int i;  
    for(i=0;i<8;i++){
		P[i]=(*ptr_text)^ivec[i];  
		ptr_text++;
	}
    
 // find number of block to calculate resultlen
 // Encrypt first block

	BF_ecb_encrypt(&P[0], out, key, BF_ENCRYPT);

	int block_number=0;

	bufsize = bufsize - 8;

	if(bufsize<0){
		block_number=1;
	}
	else{
		block_number++;
	}

	int j = SIZE;
	int k;
	i = 0;	
// XOR and encrypt blocks according to chainning prensible 
	while(bufsize>0){
		for(k=0;k<SIZE;k++){
			P[j++]= (*out) ^ (* ptr_text); 
			out++;
			ptr_text++; 
     	}
		i=i+SIZE;  	
		BF_ecb_encrypt(&P[i], out, key, BF_ENCRYPT);
	  	bufsize = bufsize - SIZE;
	  	block_number++;
	}
	*resultlen=block_number*SIZE;
	return (void *) ptr_cipher;
}

void *fs_decrypt(void *ciphertext, int bufsize, char *keystr,int *resultlen){
	
// Random initial vector declaration
	int a;
    char ivec[8];
    for(a=0; a<8; a++) ivec[a] = 'i';

	unsigned char *out2 = (unsigned char *)calloc(SIZE+1, sizeof(char)); // out2= plaintext
	unsigned char * ptr_cipher=(unsigned char *) ciphertext;
	unsigned char * cipher=(unsigned char *) ciphertext;  
    unsigned char P[bufsize];
	unsigned char *p=P;
 
//Decrypt ciphertext   	          
    BF_ecb_encrypt(ptr_cipher, out2, key, BF_DECRYPT);

// XOR with initial vector
    int k;
    for(k=0;k<8;k++){
      P[k]= (*out2)^ivec[k]; 
	  out2++;
	}
// Decrypt other blocks to obtain plaintext
         int j=0;
         int i=8; 
	 bufsize = bufsize - SIZE;
        while(bufsize>0){              
			ptr_cipher = ptr_cipher+ SIZE;
			BF_ecb_encrypt(ptr_cipher, out2, key, BF_DECRYPT);
            for(k=0;k<SIZE;k++,i++,j++){
                P[i]=(*cipher)^(*out2);
			  	out2++;
			 	cipher++;
            }
			bufsize = bufsize - SIZE;
	    }
 	*resultlen=strlen((const char*) P)+1;
	return (void *) p;
}




// reference
//https://github.com/amoghlale/CBC-ECB-Mode/


