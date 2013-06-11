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
#include <signal.h>
#include <stdint.h>
#include "md5.h"

#define INT_LEN sizeof(uint32_t)
#define MD5_LEN 16

int pgid;
int proc_num;
unsigned char crypto_word[MD5_LEN];
char* result;
pid_t childs[40];
int gap;

const char digit_pairs[201] = {
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

void itostr(unsigned int val, char* buf,int *n)
{
	int size;char *c;
    if(val==0)
    {
		buf[*n-1] = '0';
        *n = 1;
    }

    /*if(val>=10000)
    {
        if(val>=10000000)
        {
                size=8;
        }
        else
        {
            if(val>=1000000)
                size=7;
            else if(val>=100000)
                size=6;
            else
                size=5;
        }
    }

    else
    {
        if(val>=100)
        {
            if(val>=1000)
                size=4;
            else
                size=3;
        }
        else
        {
            if(val>=10)
                size=2;
            else
                size=1;
        }
    }*/

    if(val>=1000000)
    {
        if(val>=10000000)
        {
                size=8;
        }
        else
        {
            size = 7;
        }
    }else{
        size = 6;
    }

    c = &buf[*n-1];
    while(val>=100)
    {
       int pos = val % 100;
       val /= 100;
       *(short*)(c-1)=*(short*)(digit_pairs+2*pos);
       c-=2;
    }
    while(val>0)
    {
        *c--='0' + (val % 10);
        val /= 10;
    }
	*n = size;
}

void MDPrint (unsigned char *digest)
{
    int i;

    for (i = 0; i < 16; i++)
        printf ("%02x", digest[i]);
    putchar('\n');
}

int crack_compare(char *data,int len,unsigned char* crypto_word){
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

void sig_handler(int sig){
    printf("%s\n",result);
    int i;
    for(i=0;i<proc_num;i++)
        kill(childs[i],9);
}

int main()
{
    unsigned int seq = 0;
    unsigned int i=0;
    int fifo_fd;
    struct stat statbuf;
    proc_num = 1;//get_nprocs();
    gap = 100000000 / proc_num;
    //proc_num+=2;

    result = (char*)mmap(NULL,9,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    signal(SIGUSR1,sig_handler);
    /*read from stdin*/
    for(i=0;i<16;i++){
        scanf("%2x",&crypto_word[i]);
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
        uint32_t data = seq;
        write(fifo_fd,(unsigned char *)&data,4);
    }

    //pause();
    for(seq=0;seq<proc_num;seq++){
        uint32_t temp = 0xffffffff;
        write(fifo_fd,(unsigned char *)&temp,INT_LEN);
    }

    int waitNum = 0;
    while(wait(NULL)){
        waitNum++;
        if(waitNum==proc_num)
            break;
    }

    return 0;
}

void createChildProcess(int num){
    int i=0;
    pid_t pid;
    pgid = getpid();
    unsigned char crypto[MD5_LEN];
    for(i=0;i<MD5_LEN;i++)
        crypto[i] = crypto_word[i];

    for(i=0;i<num;i++){
        pid = fork();
        if(pid==0){
            /*child process begin*/

            struct timeval tvafter,tvpre;
            struct timezone tz;
            gettimeofday (&tvpre , &tz);
            int fd;
            if((fd = open("/tmp/md5crack",O_RDONLY)) < 0)
                perror("error open fifo");

            uint32_t begin_seq;
            uint32_t end_seq;
            char temp[8];
            int dig_num = 8;
            int j;
            while(1){
                while(read(fd,(unsigned char *)&begin_seq,INT_LEN) <= 0)
                    ;
                //if(begin_seq == 0xffffffff)
                //    exit(0);
                //printf("data is :%d\n",begin_seq);
                unsigned int seq;
                end_seq = begin_seq + gap;
                for(seq = begin_seq;seq<end_seq;seq++){

                    //int dig_num = digit_num(seq);
                    //sprintf(temp + 8 - dig_num,"%d",seq);
                    //dig_num = digit_num(seq);

                    itostr(seq,temp,&dig_num);
                    int t = 8 - dig_num;
                    for(j= 0; j < t;j++)
                        temp[j] = '0';

                    //j = 8 - dig_num;
                    j = ( dig_num > 6 ) * (6-dig_num) + 2;
                    //j = dig_num > 6 ? 8 - dig_num : 2;

                    for(; j>=0 ; j--){
                        int len = 8-j;
                        if(crack_compare(temp+j,len,crypto) == 0){
                            //write(1,temp+j,len);
                            //putchar('\n');
                            result[len] = 0;
                            memcpy(result,temp+j,len);
                            gettimeofday (&tvafter , &tz);
                            printf("花费时间:%d\n",(tvafter.tv_sec-tvpre.tv_sec)*1000+(tvafter.tv_usec-tvpre.tv_usec)/1000);
                            //killpg(pgid,9);
                            kill(pgid,SIGUSR1);
                            exit(0);
                        }
                    }
                }
            }

            /*child process end*/
            exit(0);
        }else{
            childs[i] = pid;
        }
    }
}
