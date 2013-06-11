#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <mqueue.h>
#include <signal.h>
#include <stdint.h>
#include "md5.h"

#define MD5_LEN 16


int pgid;
int proc_num;
unsigned char crypto_word[MD5_LEN];
char* result;
pid_t childs[40];
uint32_t beginSeq[10];
char BUFF[40];
int gap;

void to()
{
    int i;
    for(i=0;i<32;i=i+2)
    {
        if(BUFF[i]<='9'&&BUFF[i+1]<='9')
            crypto_word[i/2]=(BUFF[i]-'0')*16+(BUFF[(i+1)]-'0');
        if(BUFF[i]<='9'&&BUFF[i+1]>='a')
            crypto_word[i/2]=(BUFF[i]-'0')*16+(BUFF[(i+1)]-'a'+10);
        if(BUFF[i+1]<='9'&&BUFF[i]>='a')
            crypto_word[i/2]=(BUFF[i]-'a'+10)*16+(BUFF[(i+1)]-'0');
        if(BUFF[i+1]>='a'&&BUFF[i]>='a')
            crypto_word[i/2]=(BUFF[i]-'a'+10)*16+(BUFF[(i+1)]-'a'+10);
    }
}

int digit_num(int x)
{
    if (x >= 10000)
    {
        if (x >= 10000000)
        {
            return 8;
        }
        if (x >= 100000)
        {
            if (x >= 1000000)
                return 7;
            return 6;
        }
        return 5;
    }
    if (x >= 100)
    {
        if (x >= 1000)
            return 4;
        return 3;
    }
    if (x >= 10)
        return 2;

    return 1;
}

void MDPrint (unsigned char *digest)
{
    int i;

    for (i = 0; i < 16; i++)
        printf ("%02x", digest[i]);
    putchar('\n');
}

int crack_compare(unsigned char *data,int len,unsigned char* crypto_word)
{
    MD5_CTX mdContext;
    uint32_t *ptr1,*ptr2;

    MD5Init (&mdContext);
    MD5Update (&mdContext, data, len);
    MD5Final (&mdContext);

    int i = 0;
    for(; i<MD5_LEN; i++)
    {
        if(mdContext.digest[i]!=crypto_word[i])
            return 1;
    }
    return 0;
}

void sig_handler(int sig)
{
    int i;
    for(i=0; i<proc_num; i++)
        kill(childs[i],9);
}

int main()
{
    uint32_t seq = 0;
    unsigned int i=0;
    proc_num = get_nprocs();
    gap = 100000000 / proc_num;

    signal(SIGUSR1,sig_handler);
    /*read from stdin*/
    for(i=0; i<16; i++)
    {
        scanf("%2x",&crypto_word[i]);
    }

    //scanf("%s",BUFF);
    //to();

    for(i=0; i<proc_num; i++)
    {
        beginSeq[i] = gap * i;
    }

    createChildProcess(proc_num);

    int waitNum = 0;
    while(wait(NULL))
    {
        waitNum++;
        if(waitNum==proc_num)
            break;
    }

    return 0;
}

void createChildProcess(int num)
{
    int i=0;
    pid_t pid;
    pgid = getpid();

    for(i=0; i<num; i++)
    {
        pid = fork();
        if(pid==0)
        {
            /*child process begin*/

            //struct timeval tvafter,tvpre;
            //struct timezone tz;
            //gettimeofday (&tvpre , &tz);

            uint32_t begin_seq;
            uint32_t end_seq;
            char temp[10];
            int j;
            uint32_t seq;
            begin_seq = beginSeq[i];
            end_seq = begin_seq + gap;
            for(seq = 0; seq<100000000; seq++)
            {
                /*
                int dig_num = digit_num(seq);
                int t = 8 - dig_num;
                sprintf(temp + t,"%d",seq);

                for(j= 0; j < t; j++)
                    temp[j] = '0';
                j = dig_num > 6 ? t : 2;
                for(; j>=0 ; j--)
                {
                    int len = 8-j;
                    if(crack_compare(temp+j,len,crypto_word) == 0)
                    {
                        write(1,temp+j,len);
                        fflush(stdout);
                        //putchar('\n');
                        //result[len] = 0;
                        //memcpy(result,temp+j,len);
                        //gettimeofday (&tvafter , &tz);
                        //printf("花费时间:%d\n",(tvafter.tv_sec-tvpre.tv_sec)*1000+(tvafter.tv_usec-tvpre.tv_usec)/1000);
                        //killpg(pgid,9);
                        kill(pgid,SIGUSR1);
                        exit(0);
                    }
                }*/
                if(seq<1000000){
                    sprintf(temp,"%06d",seq);
                    //printf("%s\n",temp);
                    if(crack_compare(temp,6,crypto_word) == 0){
                        write(1,temp,6);
                        fflush(stdout);
                        kill(pgid,SIGUSR1);
                        exit(0);
                    }
                    sprintf(temp,"%07d",seq);
                    if(crack_compare(temp,7,crypto_word) == 0){
                        write(1,temp,7);
                        fflush(stdout);
                        kill(pgid,SIGUSR1);
                        exit(0);
                    }
                    sprintf(temp,"%08d",seq);
                    if(crack_compare(temp,8,crypto_word) == 0){
                        write(1,temp,8);
                        fflush(stdout);
                        kill(pgid,SIGUSR1);
                        exit(0);
                    }
                }else if(seq<10000000){
                    sprintf(temp,"%07d",seq);
                    if(crack_compare(temp,7,crypto_word) == 0){
                        write(1,temp,7);
                        fflush(stdout);
                        kill(pgid,SIGUSR1);
                        exit(0);
                    }
                    sprintf(temp,"%08d",seq);
                    if(crack_compare(temp,8,crypto_word) == 0){
                        write(1,temp,8);
                        fflush(stdout);
                        kill(pgid,SIGUSR1);
                        exit(0);
                    }
                }else{
                    sprintf(temp,"%08d",seq);
                    if(crack_compare(temp,8,crypto_word) == 0){
                        write(1,temp,8);
                        fflush(stdout);
                        kill(pgid,SIGUSR1);
                        exit(0);
                    }
                }

            }

            /*child process end*/
            exit(0);
        }
        else
        {
            childs[i] = pid;
        }
    }
}
