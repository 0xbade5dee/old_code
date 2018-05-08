/* linux x86 shellcode by eSDee of Netric (www.netric.org)
 * Plays /tmp/wav ;)
 */     


char 
main[] =
        "\x31\xc0\x31\xc9\x50\x68\x2f\x77"
        "\x61\x76\x68\x2f\x74\x6d\x70\x89"
        "\xe3\xb0\x05\xcd\x80\x89\x45\x04"
        "\x31\xc0\x50\x68\x75\x64\x69\x6f"
        "\x68\x76\x2f\x2f\x61\x68\x2f\x2f"
        "\x64\x65\x89\xe3\xb1\x01\xb0\x05"
        "\xcd\x80\x89\x45\x08\x31\xc0\x31"
        "\xd2\x8b\x5d\x04\x89\xe1\x80\xed"
        "\xff\xb2\xff\xb0\x03\xcd\x80\x89"
        "\xc2\x31\xc0\x8b\x5d\x08\xb0\x04"
        "\xcd\x80\x31\xd2\xb2\xff\x39\xc2"
        "\x74\xdb\x8b\x5d\x04\x31\xc0\xb0"
        "\x06\xcd\x80\x8b\x5d\x08\x31\xc0"
        "\xb0\x06\xcd\x80\x31\xc0\xb0\x01"
        "\xcd\x80";

int
c_code()
{
        long *ptr = (long *) &ptr - 255;

        int fd1 = 0;
        int fd2 = 0;

        int a = 0;
        int b = 0;

        fd1 = open("/tmp/wav", 0);
        fd2 = open("/dev/audio", 1);

        while(1) {
                a = read(fd1, ptr, 255);
                b = write(fd2, ptr, a);
                if (a < 255) break;
        }                       

        close(fd2);
        close(fd1);

        exit();
}

int
asm_code()
{
        __asm(" 
                # fd1 = open(/tmp/wav, 0);
                xorl    %eax,   %eax
                xorl    %ecx,   %ecx
                pushl   %eax
                pushl   $0x7661772f             # The string:
                pushl   $0x706d742f             # /tmp/wav
                movl    %esp,   %ebx            
                movb    $5,     %al             # SYS_open
                int     $0x80
                movl    %eax,   4(%ebp)

                # fd2 = open(/dev/audio, 1);
                xorl    %eax,   %eax
                pushl   %eax
                pushl   $0x6f696475             
                pushl   $0x612f2f76             # The string:
                pushl   $0x65642f2f             # //dev//audio
                movl    %esp,   %ebx
                movb    $1,     %cl             # WRITEONLY
                movb    $5,     %al             # SYS_open
                int     $0x80
                movl    %eax,   8(%ebp)

                LOOP:
                        # a = read(fd1, ptr, 255);
                        xorl    %eax,   %eax
                        xorl    %edx,   %edx
                        movl    4(%ebp),%ebx
                        movl    %esp,   %ecx
                        subb    $0xff,  %ch
                        movb    $0xff,  %dl
                        movb    $3,     %al     # SYS_read
                        int     $0x80

                        # b = write(fd2, ptr, a);
                        movl    %eax,   %edx
                        xorl    %eax,   %eax
                        movl    8(%ebp),%ebx
                        movb    $4,     %al     # SYS_write
                        int     $0x80

                        xorl    %edx,   %edx
                        movb    $0x0ff, %dl
                        cmp     %eax,   %edx

                je LOOP

                # close(fd1);
                movl    4(%ebp),%ebx    
                xorl    %eax,   %eax
                movb    $6,     %al             # SYS_close
                int     $0x80           

                # close(fd2);
                movl    8(%ebp),%ebx
                xorl    %eax,   %eax
                movb    $6,     %al             # SYS_close
                int     $0x80

                # exit()
                xorl    %eax,   %eax
                movb    $1,     %al
                int     $0x80");

}