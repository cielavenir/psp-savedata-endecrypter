/*
 * SaveData En/Decrypter on PC (GPLv3+)
 * kirk-engine (C) draan / proxima
 * jpcsp (C) jpcsp team, especially CryptoEngine by hykem
 * ported by popsdeco (aka @cielavenir)
 * acknowledgement: referred SED-PC to fix the hashing algorithm
 */

#ifdef __cplusplus
extern "C"{
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <stdbool.h>
#include "libkirk/kirk_engine.h"

#define arraycopy(src,srcPos,dest,destPos,len) memmove((dest)+(destPos),(src)+(srcPos),(len))

#define hleChnnlsv_21BE78B4(ctx) memset(ctx,0,sizeof(_SD_Ctx2));
 
typedef unsigned char byte;
//typedef unsigned char u8;
typedef          char s8;
typedef unsigned int  u32_le;
typedef          int  s32_le;
 
#if defined(WIN32) || (!defined(__GNUC__) && !defined(__clang__))
        #define initstdio() setmode(fileno(stdin),O_BINARY),setmode(fileno(stdout),O_BINARY),setmode(fileno(stderr),O_BINARY);
#else
        #define initstdio()
        int filelength(int fd){ //constant phrase
                struct stat st;
                fstat(fd,&st);
                return st.st_size;
        }
#endif

#ifdef __cplusplus
}
#endif