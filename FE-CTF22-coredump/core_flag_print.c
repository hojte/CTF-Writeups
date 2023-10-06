#include <stdio.h>
#include <string.h>

int main() //sub_55FF00686125()
{
  char buf[40]; // [rsp+0h] [rbp-30h] BYREF
  char v2[40]; // [rsp+8h] [rbp-28h] BYREF
  //char v3; // [rsp+2Bh] [rbp-5h]
  //unsigned int i; // [rsp+2Ch] [rbp-4h]

  *(unsigned long long *)buf = 3256108273818481714LL;
  strcpy(v2, ":b&0-b8158e!b1:b&0-b/ 1.b5)?H");
  decrypt_buffer(&buf);
  decrypt_buffer(&v2);
  printf("%s", buf);
  printf("%s", v2);
  return 1; //sys_write(1u, buf, 0x25uLL);
}

void decrypt_buffer(char *buffer) {
  for (int i = 0; i <= 40; ++i )
  {
    char v3;
    v3 = buffer[i];
    v3 ^= 0x42u;
    if ( v3 > 64 && v3 <= 90 )
      v3 = (v3 - 100) % 26 + 90;
    if ( v3 > 96 && v3 <= 122 )
      v3 = (v3 - 132) % 26 + 122;
    buffer[i] = v3;
  }
}