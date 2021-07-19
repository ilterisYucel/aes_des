#include <iostream>
#include <fstream>
#include <limits>
#include <string>
#include <cctype>
#include <stdlib.h>
#include <time.h>
#include "AES.h"

struct commandParser{
    char op[4];
    char infile[70];
    char outfile[70];
    char algorithm[4];
    char mode[4];
    char keyfile[70];
};

char* toLowerString(char* string){

    int i;
    for(i = 0; i < strlen(string)+1; i++){
        string[i] = tolower(string[i]);
        //cout << (char) tolower(string[i]) << "\n";
    }
    
    return string;

}

int main(int argc, char* argv[]){
    unsigned char plain[2048];
   unsigned char key[16];
    unsigned char iv[16]; 
    char nonce[16];
    unsigned char* c, *d;
    unsigned char *e, *f;
    unsigned char plainDes[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    unsigned char  keyDes[]  = {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned int  inLenDes = 8 * sizeof(unsigned char);
    unsigned char ivDes[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    unsigned int outLenDes = 0;
    
    struct commandParser parser;
    int i;
    
    for(i = 0; i < argc; i++){
        if(strcmp(toLowerString(argv[i]), "-e") == 0 || strcmp(toLowerString(argv[i]), "-d") == 0){
            memcpy(parser.op, argv[i], strlen(argv[i])+1);
        }else if(strcmp(toLowerString(argv[i]), "-i") == 0){
            memcpy(parser.infile, argv[i+1], strlen(argv[i+1])+1);
        }else if(strcmp(toLowerString(argv[i]), "-o") == 0){
            memcpy(parser.outfile, argv[i+1], strlen(argv[i+1])+1);
        }else if(strcmp(toLowerString(argv[i]), "aes") == 0 || strcmp(toLowerString(argv[i]), "des") == 0){
            memcpy(parser.algorithm, argv[i], strlen(argv[i])+1);
        }else if(strcmp(toLowerString(argv[i]), "ctr") == 0 || strcmp(toLowerString(argv[i]), "cbc") == 0 || strcmp(toLowerString(argv[i]), "ofb") == 0){
            memcpy(parser.mode, argv[i], strlen(argv[i])+1);
        }else{
            memcpy(parser.keyfile, argv[i], strlen(argv[i])+1);
        }
        
    }

    FILE *fp = fopen(parser.infile, "r");
    FILE *fp1 = fopen(parser.outfile, "w");
    FILE* fp2 = fopen(parser.keyfile, "r");
    FILE* fp3 = fopen("run.log", "a");
    
    char  ch;
    //unsigned char* plain;
    unsigned int outLen = 0;
    unsigned int inLen = 0;
    
    if(fp != NULL){
        ch = getc(fp);
        while(ch != EOF){
            if(ch != '\n'){
                plain[inLen++] = ch;
            }
            ch = getc(fp);
        }
        fclose(fp);
    }
    plain[inLen] = '\0';
    
    char  ch1;
    int index = 0;
    int delim = 0;
    
    if(fp2 != NULL){
        ch1 = getc(fp2);
        while(ch1 != EOF){
            if(ch1 != '\n' && ch1 != ' '){
                if(ch1 != '-' && delim == 0){
                    key[index++] = ch1;
                }else if(ch1 != '-' && delim == 1){
                    iv[index++] = ch1;
                }else if (ch1 != '-' && delim == 2){
                    nonce[index++] = ch1;
                }else if(ch1 == '-'){
                    index = 0;
                    delim++;
                }
            }
            ch1 = getc(fp2);
        }
        fclose(fp2);
    }

    char* nonePtr;
    unsigned int nonceVal = strtol(nonce, &nonePtr, 16);
    
    AES aes(128);
    
    clock_t begin = clock();
    clock_t end;

    if(strcmp(parser.algorithm, "aes") == 0 && strcmp(parser.op, "-e") == 0 && strcmp(parser.mode, "cbc") == 0){
        
        e = aes.EncryptCBC(plain, inLen, key, iv, outLen);
        f = aes.DecryptCBC(e, inLen, key, iv);
        end = clock();
        
        fprintf(fp1, "%s", "Plain Hex Values\n");
        for(i = 0; i < inLen; i++){
            fprintf(fp1, "%02X ", plain[i]);
        }
        fputc('\n', fp1);
        fputc('\n', fp1);
        
        fprintf(fp1, "%s", "After Encrpytion Process\n");
        for(i = 0; i < inLen; i++){

            fprintf(fp1, "%02X ", e[i]);
        }
        fputc('\n', fp1);
        fputc('\n', fp1);
        
        fprintf(fp1, "%s", "After Decryption Process\n");
        for(i = 0; i < inLen; i++){

            fprintf(fp1, "%02X ", f[i]);
        }
        fputc('\n', fp1);
        fputc('\n', fp1);
        
        fclose(fp1);
        
        strcpy(parser.algorithm, "AES");
        strcpy(parser.op, "enc");
        strcpy(parser.mode, "CBC");
    }
    
    else if(strcmp(parser.algorithm, "aes") == 0 && strcmp(parser.op, "-e") == 0 && strcmp(parser.mode, "ctr") == 0){
        e = aes.EncryptCTR(plain, 19, key, iv, outLen, (long unsigned int)nonce);
        f = aes.DecryptCTR(e, 19, key, iv, (long unsigned int)nonce);
        end = clock();
        
        fprintf(fp1, "%s", "Plain Hex Values\n");
        for(i = 0; i < inLen; i++){
            
            fprintf(fp1, "%02X ", plain[i]);
        }
        fputc('\n', fp1);
        fputc('\n', fp1);
        
        fprintf(fp1, "%s", "After Encrpytion Process\n");
        for(i = 0; i < inLen; i++){

            fprintf(fp1, "%02X ", e[i]);
        }
        fputc('\n', fp1);
        fputc('\n', fp1);
        
        fprintf(fp1, "%s", "After Decryption Process\n");
        for(i = 0; i < inLen; i++){

            fprintf(fp1, "%02X ", f[i]);
        }
        fputc('\n', fp1);
        fputc('\n', fp1);
        
        fclose(fp1);
        strcpy(parser.algorithm, "AES");
        strcpy(parser.op, "enc");
        strcpy(parser.mode, "CTR");
    }    
    
    
    else if(strcmp(parser.algorithm, "aes") == 0 && strcmp(parser.op, "-e") == 0 && strcmp(parser.mode, "ofb") == 0){
        e = aes.EncryptOFB(plain, inLen, key, iv, outLen);
        f = aes.DecryptOFB(e, inLen, key, iv);
        end = clock();
        
        fprintf(fp1, "%s", "Plain Hex Values\n");
        for(i = 0; i < inLen; i++){
            
            fprintf(fp1, "%02X ", plain[i]);
        }
        fputc('\n', fp1);
        fputc('\n', fp1);
        
        fprintf(fp1, "%s", "After Encrpytion Process\n");
        for(i = 0; i < inLen; i++){

            fprintf(fp1, "%02X ", e[i]);
        }
        fputc('\n', fp1);
        fputc('\n', fp1);
        
        fprintf(fp1, "%s", "After Decryption Process\n");
        for(i = 0; i < inLen; i++){

            fprintf(fp1, "%02X ", f[i]);
        }
        fputc('\n', fp1);
        fputc('\n', fp1);
        
        fclose(fp1);
        strcpy(parser.algorithm, "AES");
        strcpy(parser.op, "enc");
        strcpy(parser.mode, "OFB");
    }
    
    
    else if(strcmp(parser.algorithm, "aes") == 0 && strcmp(parser.op, "-d") == 0 && strcmp(parser.mode, "cbc") == 0){
        e = aes.DecryptCBC(plain, inLen, key, iv);
        
        end = clock();
        
        fprintf(fp1, "%s", "Cipher Hex Values\n");
        for(i = 0; i < inLen; i++){
            
            fprintf(fp1, "%02X ", plain[i]);
        }
        fputc('\n', fp1);
        
        fprintf(fp1, "%s", "Plain Hex Values\n");
        for(i = 0; i < inLen; i++){
            
            fprintf(fp1, "%02X ", e[i]);
        }
        fputc('\n', fp1);
        
        fclose(fp1);
        strcpy(parser.algorithm, "AES");
        strcpy(parser.op, "dec");
        strcpy(parser.mode, "CBC");
    }
    
    else if(strcmp(parser.algorithm, "aes") == 0 && strcmp(parser.op, "-d") == 0 && strcmp(parser.mode, "ctr") == 0){
        e = aes.DecryptCTR(plain, 17, key, iv, (long unsigned int)nonce);
        end = clock();
        
        fprintf(fp1, "%s", "Cipher Hex Values\n");
        for(i = 0; i < inLen; i++){

            fprintf(fp1, "%02X ", plain[i]);
        }
        fputc('\n', fp1);
        
        fprintf(fp1, "%s", "Plain Hex Values\n");
        for(i = 0; i < inLen; i++){
            
            fprintf(fp1, "%02X ", e[i]);
        }
        fputc('\n', fp1);
        fclose(fp1);
        strcpy(parser.algorithm, "AES");
        strcpy(parser.op, "dec");
        strcpy(parser.mode, "CTR");
    }    
    
    
    else if(strcmp(parser.algorithm, "aes") == 0 && strcmp(parser.op, "-d") == 0 && strcmp(parser.mode, "ofb") == 0){
        e = aes.DecryptOFB(plain, inLen, key, iv);
        end = clock();
        
        fprintf(fp1, "%s", "Cipher Hex Values\n");
        for(i = 0; i < inLen; i++){
            
            fprintf(fp1, "%02X ", plain[i]);
        }
        fputc('\n', fp1);
        
        fprintf(fp1, "%s", "Plain Hex Values\n");
        for(i = 0; i < inLen; i++){
            
            fprintf(fp1, "%02X ", e[i]);
        }
        fputc('\n', fp1);
        fclose(fp1);
        
        strcpy(parser.algorithm, "AES");
        strcpy(parser.op, "dec");
        strcpy(parser.mode, "OFB");
    } 
    
    
    
    
    
    else if(strcmp(parser.algorithm, "des") == 0 && strcmp(parser.op, "-e") == 0 && strcmp(parser.mode, "cbc") == 0){
        e = aes.EncryptDESCBC(plain, inLen, key, iv, outLen);
        f = aes.DecryptDESCBC(e, inLen, key, iv);
        end = clock();
        
        fprintf(fp1, "%s", "Plain Hex Values\n");
        for(i = 0; i < inLen; i++){
            
            fprintf(fp1, "%02X ", plain[i]);
        }
        fputc('\n', fp1);
        fputc('\n', fp1);
        
        fprintf(fp1, "%s", "After Encrpytion Process\n");
        for(i = 0; i < inLen; i++){

            fprintf(fp1, "%02X ", e[i]);
        }
        fputc('\n', fp1);
        fputc('\n', fp1);
        
        fprintf(fp1, "%s", "After Decryption Process\n");
        for(i = 0; i < inLen; i++){

            fprintf(fp1, "%02X ", f[i]);
        }
        fputc('\n', fp1);
        fputc('\n', fp1);
        
        fclose(fp1);
        
        strcpy(parser.algorithm, "DES");
        strcpy(parser.op, "enc");
        strcpy(parser.mode, "CBC");
    }
    
    else if(strcmp(parser.algorithm, "des") == 0 && strcmp(parser.op, "-e") == 0 && strcmp(parser.mode, "ctr") == 0){
        e = aes.EncryptDESCTR(plain, 8, key, iv, outLen, (long unsigned int)nonce);
        f = aes.DecryptDESCTR(e, 8, key, iv, (long unsigned int)nonce );
        end = clock();
        
        fprintf(fp1, "%s", "Plain Hex Values\n");
        for(i = 0; i < inLen; i++){
            
            fprintf(fp1, "%02X ", plain[i]);
        }
        fputc('\n', fp1);
        fputc('\n', fp1);
        
        fprintf(fp1, "%s", "After Encrpytion Process\n");
        for(i = 0; i < inLen; i++){

            fprintf(fp1, "%02X ", e[i]);
        }
        fputc('\n', fp1);
        fputc('\n', fp1);
        
        fprintf(fp1, "%s", "After Decryption Process\n");
        for(i = 0; i < inLen; i++){

            fprintf(fp1, "%02X ", f[i]);
        }
        fputc('\n', fp1);
        fputc('\n', fp1);
        
        fclose(fp1);
        
        strcpy(parser.algorithm, "DES");
        strcpy(parser.op, "enc");
        strcpy(parser.mode, "CTR");
    }    
    
    
    else if(strcmp(parser.algorithm, "des") == 0 && strcmp(parser.op, "-e") == 0 && strcmp(parser.mode, "ofb") == 0){
        e = aes.EncryptDESOFB(plain, inLen, key, iv, outLen);
        f = aes.DecryptDESOFB(e, inLen, key, iv);
        end = clock();
        
        fprintf(fp1, "%s", "Plain Hex Values\n");
        for(i = 0; i < inLen; i++){
            
            fprintf(fp1, "%02X ", plain[i]);
        }
        
        fputc('\n', fp1);
        fputc('\n', fp1);
        
        fprintf(fp1, "%s", "After Encrpytion Process\n");
        for(i = 0; i < inLen; i++){

            fprintf(fp1, "%02X ", e[i]);
        }
        fputc('\n', fp1);
        fputc('\n', fp1);
        
        fprintf(fp1, "%s", "After Decryption Process\n");
        for(i = 0; i < inLen; i++){

            fprintf(fp1, "%02X ", f[i]);
        }
        fputc('\n', fp1);
        fputc('\n', fp1);
        
        fclose(fp1);        
        strcpy(parser.algorithm, "DES");
        strcpy(parser.op, "enc");
        strcpy(parser.mode, "OFB");
    }
    
    
    else if(strcmp(parser.algorithm, "des") == 0 && strcmp(parser.op, "-d") == 0 && strcmp(parser.mode, "cbc") == 0){
        e = aes.DecryptDESCBC(plain, inLen, key, iv);
        end = clock();
        
        fprintf(fp1, "%s", "Cipher Hex Values\n");
        for(i = 0; i < inLen; i++){
            
            fprintf(fp1, "%02X ", plain[i]);
        }
        fputc('\n', fp1);
        
        fprintf(fp1, "%s", "Plain Hex Values\n");
        for(i = 0; i < inLen; i++){
            
            fprintf(fp1, "%02X ", e[i]);
        }
        fputc('\n', fp1);
        fclose(fp1);
        
        strcpy(parser.algorithm, "DES");
        strcpy(parser.op, "dec");
        strcpy(parser.mode, "CBC");
    }
    
    else if(strcmp(parser.algorithm, "des") == 0 && strcmp(parser.op, "-d") == 0 && strcmp(parser.mode, "ctr") == 0){
        e = aes.DecryptDESCTR(plain, 9, key, iv, (long unsigned int)nonce);
        end = clock();
        
        fprintf(fp1, "%s", "Cipher Hex Values\n");
        for(i = 0; i < inLen; i++){
            
            fprintf(fp1, "%02X ", plain[i]);
        }
        fputc('\n', fp1);
        
        fprintf(fp1, "%s", "Plain Hex Values\n");
        for(i = 0; i < inLen; i++){
            
            fprintf(fp1, "%02X ", e[i]);
        }
        fputc('\n', fp1);
        fclose(fp1);
        
        strcpy(parser.algorithm, "DES");
        strcpy(parser.op, "dec");
        strcpy(parser.mode, "CTR");
    }    
    
    
    else if(strcmp(parser.algorithm, "des") == 0 && strcmp(parser.op, "-d") == 0 && strcmp(parser.mode, "ofb") == 0){
        e = aes.DecryptDESOFB(plain, inLen, key, iv);
        end = clock();
        
        fprintf(fp1, "%s", "Cipher Hex Values\n");
        for(i = 0; i < inLen; i++){
            
            fprintf(fp1, "%02X ", plain[i]);
        }
        fputc('\n', fp1);
        
        fprintf(fp1, "%s", "Plain Hex Values\n");
        for(i = 0; i < inLen; i++){
            
            fprintf(fp1, "%02X ", e[i]);
        }
        fputc('\n', fp1);
        fclose(fp1);
        
        strcpy(parser.algorithm, "DES");
        strcpy(parser.op, "dec");
        strcpy(parser.mode, "OFB");
    }
    
    double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
    
    fprintf(fp3, "%s %s %s %s %s %f\n", parser.infile, parser.outfile, parser.op, parser.algorithm, parser.mode, time_spent);
    
    fclose(fp3);       
       
    return 0;
}
