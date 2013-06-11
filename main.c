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

#define INT_LEN sizeof(uint32_t)
#define MD5_LEN 16

#define MSGQUEUE "/md5_crack"
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
    //return compare(mdContext.digest,crypto_word);

}

void sig_handler(int sig)
{
    int i;
    for(i=0; i<proc_num; i++)
        kill(childs[i],9);
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
    int fifo_fd;
    struct stat statbuf;
    proc_num = get_nprocs();
    gap = 100000;//100000000 / proc_num;

    signal(SIGUSR1,sig_handler);
    /*read from stdin*/
    scanf("%s",BUFF);
    to();

    if(proc_num == 1)
    {
        one_proc();
        exit(0);
    }

    if(stat("/tmp/md5crack",&statbuf)==0){
        if(remove("/tmp/md5crack") < 0)
            perror("remove");
    }

    if(mkfifo("/tmp/md5crack",0666) < 0)
        perror("make fifo");

    createChildProcess(proc_num);

    if((fifo_fd = open("/tmp/md5crack",O_WRONLY)) < 0)
        perror("open fifo error");

    for(;seq<100000000;seq+=gap){
        write(fifo_fd,&seq,4);
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
        if(crack_compare(temp,8,crypto) == 0)
        {
            write(1,temp,8);
            fflush(stdout);
            exit(0);
        }
        if(*temp=='0')
        {
            if(crack_compare(temp+1,7,crypto) == 0)
            {
                write(1,temp+1,7);
                fflush(stdout);
                exit(0);
            }
            if(temp[1]=='0')
            {
                if(crack_compare(temp+2,6,crypto) == 0)
                {
                    write(1,temp+2,6);
                    fflush(stdout);
                    exit(0);
                }
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

            //struct timeval tvafter,tvpre;
            //struct timezone tz;
            //gettimeofday (&tvpre , &tz);
            int fd;
            if((fd = open("/tmp/md5crack",O_RDONLY)) < 0)
                perror("error open fifo");

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
                while(read(fd,(unsigned char *)&begin_seq,4) <= 0)
                    ;

                end_seq = begin_seq + gap;
                itostr(begin_seq,temp);
                for(seq = begin_seq; seq<end_seq; seq++)
                {
                    if(crack_compare(temp,8,crypto) == 0)
                    {
                        write(1,temp,8);
                        fflush(stdout);
                        //gettimeofday (&tvafter , &tz);
                        //printf("花费时间:%d\n",(tvafter.tv_sec-tvpre.tv_sec)*1000+(tvafter.tv_usec-tvpre.tv_usec)/1000);
                        //killpg(pgid,9);
                        kill(pgid,SIGUSR1);
                        exit(0);
                    }
                    if(*temp=='0')
                    {
                        if(crack_compare(temp+1,7,crypto) == 0)
                        {
                            write(1,temp+1,7);
                            fflush(stdout);
                            kill(pgid,SIGUSR1);
                            exit(0);
                        }
                        if(temp[1]=='0')
                        {
                            if(crack_compare(temp+2,6,crypto) == 0)
                            {
                                write(1,temp+2,6);
                                fflush(stdout);
                                kill(pgid,SIGUSR1);
                                exit(0);
                            }
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
