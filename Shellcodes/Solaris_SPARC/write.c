/* Solaris sparc shellcode by eSDee of Netric (www.netric.org)
 * write(stdout,"netric was here\n", 16); exit();
 */

#include <stdio.h>

char
shellcode[]=

   // write(stdout,"netric was here\n", 16);
        
  "\x90\x10\x20\x01"  // mov  1, %o0
  "\x21\x1b\x99\x5d"  // sethi  %hi(0x6e657400), %l0
  "\xa0\x14\x20\x72"  // or  %l0, 0x72, %l0      ! 0x6e657472
  "\x23\x1a\x58\xc8"  // sethi  %hi(0x69632000), %l1
  "\xa2\x14\x60\x77"  // or  %l1, 0x77, %l1      ! 0x69632077
  "\x25\x18\x5c\xc8"  // sethi  %hi(0x61732000), %l2
  "\xa4\x14\xa0\x68"  // or  %l2, 0x68, %l2      ! 0x61732068
  "\x27\x19\x5c\x99"  // sethi  %hi(0x65726400), %l3
  "\xa6\x14\xe1\x0a"  // or  %l3, 0x10a, %l3     ! 0x6572650a
  "\x92\x23\xa0\x10"  // sub  %sp, 0x10, %o1
  "\xe0\x3b\xbf\xf0"  // std  %l0, [ %sp + -16 ]
  "\xe4\x3b\xbf\xf8"  // std  %l2, [ %sp + -8 ]
  "\x94\x10\x20\x10"  // mov  0x10, %o2
  "\x82\x10\x20\x04"  // mov  4, %g1
  "\x91\xd0\x20\x08"  // ta  8
  
        // exit();
        
  "\x82\x10\x20\x01"  // mov  1, %g1
  "\x91\xd0\x20\x08";  // ta  8


int
main()
{
        void (*funct) ();
        (long) funct = &shellcode;
        funct();
}