//PSP SaveData En/Decrypter PPSSPP backend

#include "endecrypter.h"

bool isNullKey(u8 *key){
	if(!key)return true;
	int i=0;
	for(;i<16;i++)if(key[i])return false;
	return true;
}

/*
 This file is part of Jpcsp/PPSSPP.

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with the program. If not, see <http://www.gnu.org/licenses/>.
*/

typedef struct _pspChnnlsvContext1 {
	/** Cipher mode */
	s32_le	mode;

	/** Context data */
	u8	result[0x10];
	u8  key[0x10];
	s32_le	keyLength;
} pspChnnlsvContext1;

typedef struct _pspChnnlsvContext2 {
	/** Context data */
	s32_le mode;
	s32_le unkn;
	u8  cryptedData[0x92];
} pspChnnlsvContext2;

u8 dataBuf[2048+20+20];
u8* dataBuf2 = dataBuf + 20;
u8 kirkHeader[40]; //I don't know why this must be global...

static const u8 hash198C[16] = {0xFA, 0xAA, 0x50, 0xEC, 0x2F, 0xDE, 0x54, 0x93, 0xAD, 0x14, 0xB2, 0xCE, 0xA5, 0x30, 0x05, 0xDF};
static const u8 hash19BC[16] = {0xCB, 0x15, 0xF4, 0x07, 0xF9, 0x6A, 0x52, 0x3C, 0x04, 0xB9, 0xB2, 0xEE, 0x5C, 0x53, 0xFA, 0x86};

static const u8 key19CC[16]  = {0x70, 0x44, 0xA3, 0xAE, 0xEF, 0x5D, 0xA5, 0xF2, 0x85, 0x7F, 0xF2, 0xD6, 0x94, 0xF5, 0x36, 0x3B};
static const u8 key19DC[16]  = {0xEC, 0x6D, 0x29, 0x59, 0x26, 0x35, 0xA5, 0x7F, 0x97, 0x2A, 0x0D, 0xBC, 0xA3, 0x26, 0x33, 0x00};
static const u8 key199C[16]  = {0x36, 0xA5, 0x3E, 0xAC, 0xC5, 0x26, 0x9E, 0xA3, 0x83, 0xD9, 0xEC, 0x25, 0x6C, 0x48, 0x48, 0x72};
static const u8 key19AC[16]  = {0xD8, 0xC0, 0xB0, 0xF3, 0x3E, 0x6B, 0x76, 0x85, 0xFD, 0xFB, 0x4D, 0x7D, 0x45, 0x1E, 0x92, 0x03};

void *memxor(void * dest, const void * src, size_t n)
{
  char const *s = (char const*)src;
  char *d = (char*)dest;

  for (; n > 0; n--)
	*d++ ^= *s++;

  return dest;
}

// The reason for the values from *FromMode calculations are not known.
int numFromMode(int mode)
{
	int num = 0;
	switch(mode)
	{
	case 1:
		num = 3;
		break;
	case 2:
		num = 5;
		break;
	case 3:
		num = 12;
		break;
	case 4:
		num = 13;
		break;
	case 6:
		num = 17;
		break;
	default:
		num = 16;
		break;
	}
	return num;
}
int numFromMode2(int mode)
{
	int num = 18;
	if (mode == 1)
		num = 4;
	else if (mode == 3)
		num = 14;
	return num;
}

int typeFromMode(int mode)
{
	return (mode == 1 || mode == 2) ? 83 :
		  ((mode == 3 || mode == 4) ? 87 : 100);	
}

int kirkSendCmd(u8* data, int length, int num, bool encrypt)
{
	*(int*)(data+0) = encrypt ? KIRK_MODE_ENCRYPT_CBC : KIRK_MODE_DECRYPT_CBC;
	*(int*)(data+4) = 0;
	*(int*)(data+8) = 0;
	*(int*)(data+12) = num;
	*(int*)(data+16) = length;

	if (sceUtilsBufferCopyWithRange(data, length + 20, data, length + 20, encrypt ? KIRK_CMD_ENCRYPT_IV_0 : KIRK_CMD_DECRYPT_IV_0))
		return -257;

	return 0;
}

int kirkSendFuseCmd(u8* data, int length, bool encrypt)
{
	*(int*)(data+0) = encrypt ? KIRK_MODE_ENCRYPT_CBC : KIRK_MODE_DECRYPT_CBC;
	*(int*)(data+4) = 0;
	*(int*)(data+8) = 0;
	*(int*)(data+12) = 256;
	*(int*)(data+16) = length;

	// Note: CMD 5 and 8 are not available, will always return -1
	if (sceUtilsBufferCopyWithRange(data, length + 20, data, length + 20, encrypt ? KIRK_CMD_ENCRYPT_IV_FUSE : KIRK_CMD_DECRYPT_IV_FUSE))
		return -258;

	return 0;
}

int sub_15B0(u8* data, int alignedLen, u8* buf, int val)
{
	u8 sp0[16];
	memcpy(sp0, data+alignedLen+4, 16);

	int res = kirkSendCmd(data, alignedLen, val, false);
	if (res)
		return res;

	memxor(data, buf, 16);
	memcpy(buf, sp0, 16);
	return 0;
}

int sub_0000(u8* data_out, u8* data, int alignedLen, u8* data2, int& data3, int mode)
{
	memcpy(data_out+20, data2, 16);
	// Mode 1:2 is 83, 3:4 is 87, 5:6 is 100
	int type = typeFromMode(mode);
	int res;

	if (type == 87)
		memxor(data_out+20, key19AC, 16);
	else if (type == 100)
		memxor(data_out+20, key19DC, 16);

	// Odd is Cmd, Even is FuseCmd
	switch(mode)
	{
	case 2: case 4:	case 6:	res = kirkSendFuseCmd(data_out, 16, false);
	break;
	case 1:	case 3:	default:res = kirkSendCmd(data_out, 16, numFromMode2(mode), false);
	break;
	}
	if (type == 87)
		memxor(data_out, key199C, 16);
	else if (type == 100)
		memxor(data_out, key19CC, 16);

	if (res)
		return res;

	u8 sp0[16], sp16[16];
	memcpy(sp16, data_out, 16);
	if (data3 == 1)
	{
		memset(sp0, 0, 16);
	}
	else
	{
		memcpy(sp0, sp16, 12);
		*(u32*)(sp0+12) = data3-1;
	}

	if (alignedLen > 0)
	{
		for(int i = 20; i < alignedLen + 20; i += 16)
		{
			memcpy(data_out+i, sp16, 12);
			*(u32*)(data_out+12+i) = data3;
			data3++;
		}
	}

	res = sub_15B0(data_out, alignedLen, sp0, type);
	if (res)
		return res;

	if (alignedLen > 0)
		memxor(data, data_out, alignedLen);

	return 0;
}

int sub_1510(u8* data, int size, u8* result , int num)
{
	memxor(data+20, result, 16);

	int res = kirkSendCmd(data, size, num, true);
	if(res)
		return res;

	memcpy(result, data+size+4, 16);
	return 0;
}

int sub_17A8(u8* data)
{
	if (sceUtilsBufferCopyWithRange(data, 20, 0, 0, 14) == 0)
		return 0;
	return -261;
}

int sceSdSetIndex_(pspChnnlsvContext1& ctx, int value)
{
	ctx.mode = value;
	memset(ctx.result, 0, 16);
	memset(ctx.key, 0, 16);
	ctx.keyLength = 0;
	return 0;
}

int sceSdGetLastIndex_(pspChnnlsvContext1& ctx, u8* in_hash, u8* in_key)
{
	if(ctx.keyLength >= 17)
		return -1026;

	int num = numFromMode(ctx.mode);

	memset(dataBuf2, 0, 16);

	int res = kirkSendCmd(dataBuf, 16, num, true);
	if(res)
		return res;

	u8 data1[16], data2[16];

	memcpy(data1, dataBuf2, 16);
	int tmp1 = (data1[0] & 0x80) ? 135 : 0;

	for(int i = 0; i < 15; i++)
	{
		u8 val1 = data1[i] << 1;
		u8 val2 = data1[i+1] >> 7;
		data1[i] = val1 | val2;
	}

	u8 tmp2 = data1[15] << 1;
	tmp2 = tmp1 ^ tmp2;
	data1[15] = tmp2;

	if(ctx.keyLength < 16)
	{
		tmp1 = 0;
		if((s8)data1[0] < 0)
		{
			tmp1 = 135;
		}
		for(int i = 0; i < 15; i++)
		{
			u8 val1 = data1[i] << 1;
			u8 val2 = data1[i+1] >> 7;
			data1[i] = val1 | val2;
		}
		u8 tmp2 = data1[15] << 1;
		tmp2 = tmp1 ^ tmp2;
		data1[15] = tmp2;

		int oldKeyLength = ctx.keyLength;
		*(s8*)(ctx.key + ctx.keyLength) = -128;
		int i = oldKeyLength + 1;
		if(i < 16)
			memset(ctx.key + i, 0, 16 - i);
	}

	memxor(ctx.key, data1, 16);
	memcpy(dataBuf2, ctx.key, 16);
	memcpy(data2, ctx.result, 16);

	int ret = sub_1510(dataBuf, 16, data2, num);
	if(ret)
		return ret;

	if(ctx.mode == 3 || ctx.mode == 4)
		memxor(data2, hash198C, 16);
	else if(ctx.mode == 5 || ctx.mode == 6)
		memxor(data2, hash19BC, 16);

	int cond = ((ctx.mode ^ 0x2) < 1 || (ctx.mode ^ 0x4) < 1 || ctx.mode == 6);
	if(cond != 0)
	{
		memcpy(dataBuf2, data2, 16);
		int ret = kirkSendFuseCmd(dataBuf, 16, true);
		if(ret)
			return ret;

		int res = kirkSendCmd(dataBuf, 16, num, true);
		if(res)
			return res;

		memcpy(data2, dataBuf2, 16);
	}

	if(in_key != 0)
	{
		for(int i = 0; i < 16; i++)
		{
			data2[i] = in_key[i] ^ data2[i];
		}

		memcpy(dataBuf2, data2, 16);

		int res = kirkSendCmd(dataBuf, 16, num, true);
		if(res)
			return res;

		memcpy(data2, dataBuf2, 16);
	}
	memcpy(in_hash, data2, 16);
	sceSdSetIndex_(ctx, 0);

	return 0;
}

int sceSdRemoveValue_(pspChnnlsvContext1& ctx, u8* data, int length)
{
	if(ctx.keyLength >= 17)
		return -1026;

	if(ctx.keyLength + length < 17)
	{
		memcpy(ctx.key+ctx.keyLength, data, length);
		ctx.keyLength = ctx.keyLength + length;
		return 0;
	}
	int num = numFromMode(ctx.mode);

	memset(dataBuf2, 0, 2048);
	memcpy(dataBuf2, ctx.key, ctx.keyLength);

	int len = (ctx.keyLength + length) & 0xF;
	if(len == 0) len = 16;

	int newSize = ctx.keyLength;
	ctx.keyLength = len;

	int diff = length - len;
	memcpy(ctx.key, data+diff, len);
	for(int i = 0; i < diff; i++)
	{
		if(newSize == 2048)
		{
			int res = sub_1510(dataBuf, 2048, ctx.result, num);
			if(res)
				return res;
			newSize = 0;
		}
		dataBuf2[newSize] = data[i];
		newSize++;
	}
	if(newSize)
		sub_1510(dataBuf, newSize, ctx.result, num);
	// The RE code showed this always returning 0. I suspect it would want to return res instead.
	return 0;
}

int sceSdCreateList_(pspChnnlsvContext2& ctx2, int mode, int uknw, u8* data, u8* cryptkey)
{
	ctx2.mode = mode;
	ctx2.unkn = 1;
	if (uknw == 2)
	{
		memcpy(ctx2.cryptedData, data, 16);
		if (cryptkey)
			memxor(ctx2.cryptedData, cryptkey, 16);

		return 0;
	}
	else if (uknw == 1)
	{
		u8* kirkData = kirkHeader+20;
		int res = sub_17A8(kirkHeader);
		if (res)
			return res;

		memcpy(kirkHeader+20, kirkHeader, 16);
		memset(kirkHeader+32, 0, 4);

		int type = typeFromMode(mode);
		if (type == 87)
			memxor(kirkData, key199C, 16);
		else if (type == 100)
			memxor(kirkData, key19CC, 16);

		switch (mode)
		{
		case 2:	case 4:	case 6:	res = kirkSendFuseCmd(kirkHeader, 16, true);
		break;
		case 1:	case 3:	default:res = kirkSendCmd(kirkHeader, 16, numFromMode2(mode), true);
		break;
		}

		if (type == 87)
			memxor(kirkData, key19AC, 16);
		else if (type == 100)
			memxor(kirkData, key19DC, 16);

		if (res)
			return res;

		memcpy(ctx2.cryptedData, kirkData, 16);
		memcpy(data, kirkData, 16);
		if (cryptkey)
			memxor(ctx2.cryptedData, cryptkey, 16);
	}

	return 0;
}

int sceSdSetMember_(pspChnnlsvContext2& ctx, u8* data, int alignedLen)
{
	if (alignedLen == 0)
	{
		return 0;
	}
	if ((alignedLen & 0xF) != 0)
	{
		return -1025;
	}
	int i = 0;
	u8 kirkData[20+2048];
	if ((u32)alignedLen >= (u32)2048)
	{
		for(i = 0; alignedLen >= 2048; i += 2048)
		{
			int ctx_unkn = ctx.unkn;
			int res = sub_0000(kirkData, data + i, 2048, ctx.cryptedData, ctx_unkn, ctx.mode);
			ctx.unkn = ctx_unkn;
			alignedLen -= 2048;
			if (res)
				return res;
		}
	}
	if (alignedLen == 0)
	{
		return 0;
	}
	int ctx_unkn = ctx.unkn;
	int res = sub_0000(kirkData, data + i, alignedLen, ctx.cryptedData, ctx_unkn, ctx.mode);
	ctx.unkn = ctx_unkn;
	return res;
}

int sceChnnlsv_21BE78B4_(pspChnnlsvContext2& ctx)
{
	memset(ctx.cryptedData, 0, 16);
	ctx.unkn = 0;
	ctx.mode = 0;

	return 0;
}


void DecryptSavedata(u8 *buf, int size, u8 *key) {
	// Initialize the context structs.
	int sdDecMode;
	pspChnnlsvContext1 ctx1;memset(&ctx1,0,sizeof(ctx1));
	pspChnnlsvContext2 ctx2;memset(&ctx2,0,sizeof(ctx2));

	// Setup the buffers.
	int alignedSize = ((size + 0xF) >> 4) << 4;
	byte tmpbuf[alignedSize];
	//byte hash[0x10];

	// Set the decryption mode.
	if (isNullKey(key)) {
		sdDecMode = 1;
	} else {
		// After firmware version 2.5.2 the decryption mode used is 5.
		//if (Emulator.getInstance().getFirmwareVersion() > 252) {
			sdDecMode = 5;
		//} else {
		//	sdDecMode = 3;
		//}
	}

	// Perform the decryption.
	sceSdSetIndex_(ctx1, sdDecMode);
	sceSdCreateList_(ctx2, sdDecMode, 2, buf, key);
	sceSdRemoveValue_(ctx1, buf, 0x10);
	arraycopy(buf, 0x10, tmpbuf, 0, size - 0x10);

	sceSdRemoveValue_(ctx1, tmpbuf, alignedSize);
	sceSdSetMember_(ctx2, tmpbuf, alignedSize);

	// Clear context 2.
	sceChnnlsv_21BE78B4_(ctx2);

	// Generate a file hash for this data.
	//sceSdGetLastIndex(ctx1, hash, key);
		
	// Copy back the data.
	arraycopy(tmpbuf, 0, buf, 0, size - 0x10);

	//return hash;
}

void EncryptSavedata(byte* buf, int size, byte *key, byte *hash, byte *iv) {
	// Initialize the context structs.
	int sdEncMode;
	pspChnnlsvContext1 ctx1;memset(&ctx1,0,sizeof(ctx1));
	pspChnnlsvContext2 ctx2;memset(&ctx2,0,sizeof(ctx2));

	// Setup the buffers.
	int alignedSize = ((size + 0xF) >> 4) << 4;
	byte header[0x10];memset(header,0,sizeof(header));
	byte tmpbuf[alignedSize];memset(tmpbuf,0,sizeof(tmpbuf));

	// Copy the plain data to tmpbuf.
	arraycopy(buf, 0, tmpbuf, 0, size);

	// Set the encryption mode.
	if (isNullKey(key)) {
		sdEncMode = 1;
	} else {
		// After firmware version 2.5.2 the encryption mode used is 5.
		//if (Emulator.getInstance().getFirmwareVersion() > 252) {
			sdEncMode = 5;
		//} else {
			//sdEncMode = 3;
		//}
	}

	// Generate the encryption IV (first 0x10 bytes).
	if(!iv){
		sceSdCreateList_(&ctx2, sdEncMode, 1, header, key);
	}else{
		ctx2.mode = sdEncMode;
		ctx2.unk = 0x1;
		memcpy(ctx2.buf,iv,0x10);
		if (!isNullKey(key)) {
			xorKey(ctx2.buf, 0, key, 0, 0x10);
		}
		memcpy(header,iv,0x10); //actually the same
	}
	sceSdSetIndex_(ctx1, sdEncMode);
	sceSdRemoveValue_(ctx1, header, 0x10);

	sceSdSetMember_(ctx2, tmpbuf, alignedSize);

	// Clear extra bytes.
	int i;
	for (i = 0; i < (alignedSize - size); i++) {
		tmpbuf[size + i] = 0;
	}
		
	// Encrypt the data.
	sceSdRemoveValue_(ctx1, tmpbuf, alignedSize);

	// Copy back the encrypted data + IV.
	arraycopy(header, 0, buf, 0, 0x10);
	arraycopy(tmpbuf, 0, buf, 0x10, size);

	// Clear context 2.
	sceChnnlsv_21BE78B4_(ctx2);
		
	// Generate a file hash for this data.
	sceSdGetLastIndex_(ctx1, hash, key);

	//return hash;
}

void GenerateSavedataHash(byte *data, int size, int mode, byte* key, byte *hash) {
	pspChnnlsvContext1 ctx1;memset(&ctx1,0,sizeof(ctx1));

	// Generate a new hash using a key.
	sceSdSetIndex_(ctx1, mode);
	sceSdRemoveValue_(ctx1, data, size);
	if(sceSdGetLastIndex_(ctx1, hash, NULL)<0)memset(hash,1,0x10);
		
	//return hash;
}

void UpdateSavedataHashes(byte* savedataParams, byte* data, int size) {
	// Setup the params, hashes, modes and key (empty).
	byte key[0x10];memset(key,0,sizeof(key));

	int mode = 2;
	int check_bit = 1;

	// Check for previous SAVEDATA_PARAMS data in the file.
	//Object savedataParamsOld = psf.get("SAVEDATA_PARAMS");
	//if (savedataParamsOld != null) {
		// Extract the mode setup from the already existing data.
		//byte[] savedataParamsOldArray = (byte[]) savedataParamsOld;
		mode = ((savedataParams[0] >> 4) & 0xF);
		check_bit = ((savedataParams[0]) & 0xF);
	//}
	memset(savedataParams,0,0x80);
	//if((mode&0x4)==0x4)mode=2;

	if ((mode & 0x4) == 0x4) {
		// Generate a type 6 hash.
		GenerateSavedataHash(data, size, 6, key, savedataParams+0x20);
		savedataParams[0]|=0x01;

		savedataParams[0]|=0x40;
		// Generate a type 5 hash.
		GenerateSavedataHash(data, size, 5, key, savedataParams+0x70);
	} else if((mode & 0x2) == 0x2) {
		// Generate a type 4 hash.
		GenerateSavedataHash(data, size, 4, key, savedataParams+0x20);
		savedataParams[0]|=0x01;

		savedataParams[0]|=0x20;
		// Generate a type 3 hash.
		GenerateSavedataHash(data, size, 3, key, savedataParams+0x70);
	} else {
		// Generate a type 2 hash.
		GenerateSavedataHash(data, size, 2, key, savedataParams+0x20);
		savedataParams[0]|=0x01;
	}

	if ((check_bit & 0x1) == 0x1) {
		// Generate a type 1 hash.
		GenerateSavedataHash(data, size, 1, key, savedataParams+0x10);
	}
}

unsigned int read32(const void *p){
	const unsigned char *x=(const unsigned char*)p;
	return x[0]|(x[1]<<8)|(x[2]<<16)|(x[3]<<24);
}

unsigned short read16(const void *p){
	const unsigned char *x=(const unsigned char*)p;
	return x[0]|(x[1]<<8);
}

int main(int argc, char **argv){
	kirk_init();
	initstdio();
	if(argc<3){
		fprintf(stderr,
			"[Proof of Concept/alpha] PSP Savedata En/Decrypter on PC (GPLv3+)\n"
			"kirk-engine (C) draan / proxima\n"
			"jpcsp (C) jpcsp team, especially CryptoEngine by hykem\n"
			"ported by popsdeco (aka @cielavenir)\n"
			"acknowledgement: referred SED-PC to fix the hashing algorithm\n"
			"\n"
			"Decrypt: endecrypter ENC.bin GAMEKEY.bin > DEC.bin\n"
			"Encrypt: endecrypter DEC.bin GAMEKEY.bin PARAM.SFO > ENC.bin\n"
			"Please note that PARAM.SFO is overwritten in encryption.\n"
		);
		return 1;
	}
	FILE *f=fopen(argv[1],"rb");
	int size=filelength(fileno(f));
	//int alignedSize = ((size + 0xF) >> 4) << 4;
	u8 *inbuf=(u8*)calloc(size+0x10,1);
	fread(inbuf,1,size,f);
	fclose(f);
	byte key[16];memset(key,0,16);
	if(strcasecmp(argv[2],"NULL")){
		f=fopen(argv[2],"rb");
		fread(key,1,16,f);
		fclose(f);
	}

	if(argc>3){ //enc. argv[3]=PARAM.SFO.
		f=fopen(argv[3],"r+b");
		if(f){
			int sfosize=filelength(fileno(f));
			u8 *p=(u8*)malloc(sfosize);
			fread(p,1,sfosize,f);
			if(memcmp(p,"\0PSF",4)||read32(p+4)!=0x00000101)return 1;

			int label_offset=read32(p+8);
			int data_offset=read32(p+12);
			int nlabel=read32(p+16);
			int i=0,j=0;
			for(;i<nlabel;i++){
				if(!strcmp((char*)p+label_offset+read16(p+20+16*i),"SAVEDATA_PARAMS")){
					for(;j<nlabel;j++){
						if(!strcmp(p+label_offset+read16(p+20+16*j),"SAVEDATA_FILE_LIST")){
							int paramsize=read32(p+20+16*i+8);
							u8 *param=p+data_offset+read32(p+20+16*i+12);
#if 0
							//This can be used for checking SAVEDATA_FILE_LIST hash.
							byte iv[0x10];
							byte savehash[0x10];
							memcpy(iv,inbuf,0x10);
							memcpy(savehash,p+data_offset+read32(p+20+16*j+12)+0x0d,0x10);
							DecryptSavedata(inbuf, size, key);
							EncryptSavedata(inbuf, size-0x10, key, p+data_offset+read32(p+20+16*j+12)+0x0d,iv);
							printf("%d\n",memcmp(p+data_offset+read32(p+20+16*j+12)+0x0d,savehash,0x10));
#endif
							EncryptSavedata(inbuf, size, key, p+data_offset+read32(p+20+16*j+12)+0x0d,NULL);
							fwrite(inbuf,1,size+0x10,stdout);
							//This hash is different from original one, but PSP somehow accepts it...
							UpdateSavedataHashes(param,p,sfosize);

							//write back
							fseek(f,data_offset+read32(p+20+16*i+12),SEEK_SET);
							fwrite(p+data_offset+read32(p+20+16*i+12),1,paramsize,f);
							fseek(f,data_offset+read32(p+20+16*j+12)+0x0d,SEEK_SET);
							fwrite(p+data_offset+read32(p+20+16*j+12)+0x0d,1,0x10,f);
							break;
						}
					}
					break;
				}
			}
			fclose(f);
		}
	}else{
		DecryptSavedata(inbuf, size, key);
		fwrite(inbuf,1,size-0x10,stdout);
	}
	free(inbuf);
	return 0;
}