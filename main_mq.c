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

#define MSGQUEUE "/crack"
#define MSGSIZE 4

int pgid;
int proc_num;
unsigned char crypto_word[MD5_LEN];
char* result;
pid_t childs[40];
uint32_t beginSeq[10];
char BUFF[40];
uint32_t gap;
mqd_t msgQueueId;

const char digit_pairs[201] =
{
    "00010203040506070809"
    "10111213141516171819"
    "20212223242526272829"
    "30313233343536373839"
    "40414243444546474849"
    "50515253545556575859"
    "60616263646566676869"
    "70717273747576777879"
    "80818283848586878889"
    "90919293949596979899"
};

void itostr(unsigned int val, char* buf)
{
    char *c;

    c = &buf[7];
    while(val>=100)
    {
        int pos = val % 100;
        val /= 100;
        *(uint16_t*)(c-1)=*(uint16_t*)(digit_pairs+2*pos);
        c-=2;
    }
    while(val>0)
    {
        *c--='0' + (val % 10);
        val /= 10;
    }
}

void MDPrint (unsigned char *digest)
{
    int i;

    for (i = 0; i < 16; i++)
        printf ("%02x", digest[i]);
    putchar('\n');
}

int crack_compare(char *data,int len,unsigned char* crypto_word)
{
    MD5_CTX mdContext;
    uint32_t *ptr1,*ptr2;

    MD5Init (&mdContext);
    MD5Update (&mdContext, data, len);
    MD5Final (&mdContext);

    ptr1 = (uint32_t*)(crypto_word);
    ptr2 = (uint32_t*)(mdContext.digest);
    return ( (*ptr1 != *ptr2) || (*(ptr1+1) != *(ptr2+1)) || (*(ptr1+2) != *(ptr2+2)) || (*(ptr1+3) != *(ptr2+3)) );
}

void sig_handler(int sig)
{
    int i;
    for(i=0; i<proc_num; i++)
        kill(childs[i],9);
    exit(0);
}

void to()
{
    int i;
    for(i=0; i<32; i=i+2)
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


int main()
{
    uint32_t seq = 0;
    unsigned int i=0;
    proc_num = get_nprocs();

    /*read from stdin*/
    scanf("%s",BUFF);
    to();

    if(proc_num == 1)
    {
        one_proc();
        exit(0);
    }
    gap = 20000000 / proc_num;

	signal(SIGUSR1,sig_handler);
    mq_unlink(MSGQUEUE);
    struct mq_attr attr;
    attr.mq_maxmsg = 10;
    attr.mq_msgsize = MSGSIZE;

    if((msgQueueId = mq_open(MSGQUEUE,O_RDWR|O_CREAT,0666,&attr)) < 0){
        perror("open error");
        exit(1);
    }

    createChildProcess(proc_num);

    for(; seq<100000000; seq+=gap)
    {
        mq_send(msgQueueId,&seq,4,0);
    }

    int waitNum = 0;
    while(wait(NULL))
    {
        waitNum++;
        if(waitNum==proc_num)
            break;
    }

    mq_close(msgQueueId);
    mq_unlink(MSGQUEUE);
    return 0;
}

void one_proc()
{
    uint32_t seq;
    char temp[10];
    int i;
    temp[8]=0;
    char* last = temp+7;
    char* ptr;
    memset(temp,'0',8);
    unsigned char crypto[MD5_LEN];
    for(i=0; i<MD5_LEN; i++)
        crypto[i] = crypto_word[i];

    for(seq = 0; seq<100000000; seq++)
    {
        if(seq>=10000000){
            if(crack_compare(temp,8,crypto) == 0)
            {
                write(1,temp,8);
                fflush(stdout);
                kill(pgid,SIGUSR1);
                exit(0);
            }
        }else if(seq>=1000000){
            if(crack_compare(temp+1,7,crypto) == 0)
            {
                write(1,temp+1,7);
                fflush(stdout);
                kill(pgid,SIGUSR1);
                exit(0);
            }
            if(crack_compare(temp,8,crypto) == 0)
            {
                write(1,temp,8);
                fflush(stdout);
                kill(pgid,SIGUSR1);
                exit(0);
            }
        }else{
            if(crack_compare(temp+2,6,crypto) == 0)
            {
                write(1,temp+2,6);
                fflush(stdout);
                kill(pgid,SIGUSR1);
                exit(0);
            }
            if(crack_compare(temp+1,7,crypto) == 0)
            {
                write(1,temp+1,7);
                fflush(stdout);
                kill(pgid,SIGUSR1);
                exit(0);
            }
            if(crack_compare(temp,8,crypto) == 0)
            {
                write(1,temp,8);
                fflush(stdout);
                kill(pgid,SIGUSR1);
                exit(0);
            }
        }
        ptr = last;
        while(*ptr == '9')
        {
            *ptr = '0';
            ptr--;
        }
        *ptr = *ptr + 1;
    }
}

void createChildProcess(int num)
{
    int i=0;
    pid_t pid;
    pgid = getpid();
    unsigned char crypto[MD5_LEN];
    for(i=0; i<MD5_LEN; i++)
        crypto[i] = crypto_word[i];

    for(i=0; i<num; i++)
    {
        pid = fork();
        if(pid==0)
        {
            /*child process begin*/

            struct timeval tvafter,tvpre;
            struct timezone tz;
            gettimeofday (&tvpre , &tz);

            uint32_t begin_seq;
            uint32_t end_seq;
            uint32_t seq;
            char temp[10];
            temp[8]=0;
            char* last = temp+7;
            char* ptr;
            memset(temp,'0',8);
            while(1)
            {
                mq_receive(msgQueueId,&begin_seq,4,NULL);
                end_seq = begin_seq + gap;
                itostr(begin_seq,temp);
                for(seq = begin_seq; seq<end_seq; seq++)
                {
                    if(seq>=10000000){
                        if(crack_compare(temp,8,crypto) == 0)
                        {
                            write(1,temp,8);
                            fflush(stdout);
                            kill(pgid,SIGUSR1);
                            exit(0);
                        }
                    }else if(seq>=1000000){
                        if(crack_compare(temp+1,7,crypto) == 0)
                        {
                            write(1,temp+1,7);
                            fflush(stdout);
                            kill(pgid,SIGUSR1);
                            exit(0);
                        }
                        if(crack_compare(temp,8,crypto) == 0)
                        {
                            write(1,temp,8);
                            fflush(stdout);
                            kill(pgid,SIGUSR1);
                            exit(0);
                        }
                    }else{
                        if(crack_compare(temp+2,6,crypto) == 0)
                        {
                            write(1,temp+2,6);
                            fflush(stdout);
                            kill(pgid,SIGUSR1);
                            exit(0);
                        }
                        if(crack_compare(temp+1,7,crypto) == 0)
                        {
                            write(1,temp+1,7);
                            fflush(stdout);
                            kill(pgid,SIGUSR1);
                            exit(0);
                        }
                        if(crack_compare(temp,8,crypto) == 0)
                        {
                            write(1,temp,8);
                            fflush(stdout);
                            kill(pgid,SIGUSR1);
                            exit(0);
                        }
                    }

                    ptr = last;
                    while(*ptr == '9')
                    {
                        *ptr = '0';
                        ptr--;
                    }
                    *ptr = *ptr + 1;
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
