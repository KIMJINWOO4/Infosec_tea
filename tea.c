#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>


#define _CRT_SECURE_NO_WARNINGS



unsigned int Header[8];
unsigned int Block[2];
unsigned int Key[4];
char password[16];


void makepw(char* mode){
    if(!strcmp(mode,"-e")){
        printf("input password: ");
        scanf("%s",password);
        char variate[16];
        printf("variate:");
        scanf("%s",variate);
        if(!strcmp(password,variate))
        printf("success\n");
    }
    else if(!strcmp(mode,"-d")){
        printf("input password: ");
        scanf("%s",password);
    }
    else{
        printf("mode error\n");
        exit(1);
    }
    
}
void makekey(void){
    for(int i = 0; i < 4; i++){
        int j = i * 4;
        Key[i] = ((password[j] - 32) << 24) + ((password[j + 1] - 32) << 16) + ((password[j + 2] - 32) << 8) + ((password[j + 3] - 32) << 0);
    }
}

void Encrypt(uint32_t v[2], const uint32_t k[4]) {
    uint32_t v0=v[0], v1=v[1], sum=0, i;           /* set up */
    uint32_t delta=0x9E3779B9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i<32; i++) {                         /* basic cycle start */
        sum += delta;
        v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}

void Decrypt(uint32_t v[2], const uint32_t k[4]) {
    uint32_t v0=v[0], v1=v[1], sum=0xC6EF3720, i;  /* set up; sum is (delta << 5) & 0xFFFFFFFF */
    uint32_t delta=0x9E3779B9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i<32; i++) {                         /* basic cycle start */
        v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
        v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        sum -= delta;
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
} 

void Encryption(char* mode,char* filename){
    int message = 0;
    FILE* oldfile = fopen(filename,"rb");
    char name[1000];
    strcpy(name, filename);
    strcat(name, ".tea");
    FILE* newfile= fopen(name, "wb");
    
    if(!strcmp(mode, "ecb")){
        Header[0] = 'T';
        Header[1] = 'E';
        Header[2] = 'A';
        Header[3] = '\0';
        Header[4] = 'E';
        Header[5] = 'C';
        Header[6] = 'B';
        Header[7] = '\0';

        for(int i = 0; i < 8; i += 2)
            Encrypt((Header + i), Key);     //header 암호화
        
        if(fwrite(&Header,1,8, newfile) == -1){
            exit(1);
        }
        
        while(1){
            memset(&Block, 0, sizeof(Block));
            
            message = (unsigned)fread(&Header,1,8,oldfile);
            if(message == -1){ 
                exit(1);
            }
            if(message == 0) // EOF
                break;

            Encrypt(Block, Key);
            
            if(fwrite(&Block, 1,8, newfile) == -1){    //암호화한 블록 newfile에 작성
                exit(1);
            }
        }
    }
    else if(!strcmp(mode, "cbc")){
        srand((unsigned int)time(NULL));
        unsigned int IVarr[4];
        unsigned int IV[2];

        Header[0] = 'T';
        Header[1] = 'E';
        Header[2] = 'A';
        Header[3] = '\0';
        Header[4] = 'C';
        Header[5] = 'B';
        Header[6] = 'C';
        Header[7] = '\0';

        for(int i = 0; i < 8; i += 2)
            Encrypt((Header + i), Key);

        for(int i = 0; i < 2; i++){
            for(int j = 0; j < 4; j++)
                IVarr[j] = rand() % 0x100; 
            
            if(fwrite(&IVarr, 1,8,newfile) == -1){
                exit(1);
            }
            
            IV[i] = (IVarr[0] << 24) + (IVarr[1] << 16) + (IVarr[2] << 8) + IVarr[3];
            
        }
        
        if(fwrite(&Header, 1,8,newfile) == -1){
            exit(1);
        }
        
        while(1){
            /*
             C0 = E(IV ^ P0, K)
             C1 = E(C0 ^ P1, K)
             */
            
            memset(&Block, 0, sizeof(Block));
            
            message = (unsigned)fread(&Block, 1,8, oldfile);
            if(message == -1){      //파일 읽기 오류시
                exit(printf("file read error cbc"));
            }
            if(message == 0) 
                break;
            
            Block[0] = IV[0] ^ Block[0];
            Block[1] = IV[1] ^ Block[1];
            
            Encrypt(Block, Key);
            
            if(fwrite(&Block, 1,8,newfile) == -1){ // fail
                exit(1);
            }
            
            IV[0] = Block[0];
            IV[1] = Block[1];
        }
    }
    
    fclose(oldfile);
    fclose(newfile);
    
}

void Decryption(char* mode,char* filename){
    int message = 0;
    FILE* oldfile = fopen(filename, "rb");
    char name[1000];
    strcpy(name,filename);
    for(int i = (strlen(filename)-1);i<(strlen(filename)-5);i--)
        name[i] = '\0';
    FILE* newfile = fopen(name,"wb");
    
    unsigned int checkheader[8];

    memset(&checkheader, 0x0, sizeof(checkheader));
    if(!strcmp(mode, "ecb")){
        for(int i = 0; i < 8; i++){

            message = (unsigned)fread(&checkheader[i],1,4,oldfile);
            if(message == -1){
                printf("error1");
                exit(1);
            }
            if(message == 0) {
                printf("error2");
                exit(1);
            }
                
            
        }
        for(int i = 0;i<8;i+=2)
            Decrypt((checkheader + i),Key);

        Header[0] = 'T';
        Header[1] = 'E';
        Header[2] = 'A';
        Header[3] = '\0';
        Header[4] = 'E';
        Header[5] = 'C';
        Header[6] = 'B';
        Header[7] = '\0';

        for(int i = 0; i<8;i++){
            if((unsigned int)checkheader[i]==(unsigned int)Header[i])
                continue;
            else{
                printf("gg");
                printf("header decode error");
                exit(1);
            }
        }
        while(1){

            memset(&Block, 0x0, sizeof(Block));
                
            message = (unsigned)fread(&Block,1,8,oldfile);
            
            if(message == -1){
                exit(1);
            }
            if(message == 0) // EOF
                break;
            
            Decrypt(Block, Key);
                
            if(fwrite(&Block, 1,8,newfile) == -1){ 
                printf("aa");
                exit(1);
            }
        }        
        
    }
    else if(!strcmp(mode, "cbc")){
        unsigned int TempIV[2];
        unsigned int IVarr[4];
        unsigned int IV[2];
        unsigned int checker;
        Header[0] = 'T';
        Header[1] = 'E';
        Header[2] = 'A';
        Header[3] = '\0';
        Header[4] = 'C';
        Header[5] = 'B';
        Header[6] = 'C';
        Header[7] = '\0';
        for(int i = 0; i < 2; i++){         //IV 추출
            for(int j = 0; j < 4; j++){
                memset(&checker, 0x0, sizeof(checker));
                
                message = (unsigned)fread(&checker,1,4,oldfile);
                
                if(message == -1){
                    exit(1);
                }
                if(message == 0) 
                    exit(1);
                
                IVarr[j] = checker;
            }
            IV[i] = (IVarr[0] << 24) + (IVarr[1] << 16) + (IVarr[2] << 8) + IVarr[3];
        }
        
        for(int i = 0; i < 8; i++){

            message = (unsigned)fread(&checkheader[i],1,4,oldfile);
            
            if(message == -1){
                exit(1);
            }
            if(message == 0) // EOF
                exit(1);
        }
        for(int i = 0;i<8;i+=2)
            Decrypt((checkheader + i),Key);

        for(int i = 0; i<8;i++){
            if(checkheader[i]==Header[i])
                continue;
            else{
                printf("bb");
                printf("header decode error");
                exit(1);
            }
        }
        while(1){
               memset(&Block, 0x0, sizeof(Block));
                
                message = (unsigned)fread(&Block,1,8,oldfile); // sizeof 주의
                if(message == -1){
                    exit(1);
                }
                if(message == 0) // EOF
                    break;
                    
                TempIV[0] = Block[0];
                TempIV[1] = Block[1];

                Decrypt(Block, Key);
                    
                Block[0] = IV[0] ^ Block[0];
                Block[1] = IV[1] ^ Block[1];
                        
                if(fwrite(&Block,1,8,newfile)==-1)
                    exit(1);

                IV[0] = TempIV[0];
                IV[1] = TempIV[1];
            }
    }
    
    fclose(oldfile);
    fclose(newfile);
    
    printf("Decryption End\n");
}

int main(int argv, char* args[]){

    makepw(args[1]); //pw 입력
    for(int i = (int)strlen(password);i<16;i++) //0 채우기
        password[i] = '0';
    makekey();
    if(!strcmp(args[1],"-e"))
        Encryption(args[2],args[3]);
    else if(!strcmp(args[1],"-d"))
        Decryption(args[2],args[3]);
    else
        printf("input error");
    
    return 0;
}