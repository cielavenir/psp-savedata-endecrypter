#include "endecrypter.h"

/*
 This file is part of jpcsp.

 Jpcsp is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 Jpcsp is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with Jpcsp.  If not, see <http://www.gnu.org/licenses/>.
 */

    int sdHashKey1[] = {0x40, 0xE6, 0x53, 0x3F, 0x05, 0x11, 0x3A, 0x4E, 0xA1, 0x4B, 0xDA, 0xD6, 0x72, 0x7C, 0x53, 0x4C};
    int sdHashKey2[] = {0xFA, 0xAA, 0x50, 0xEC, 0x2F, 0xDE, 0x54, 0x93, 0xAD, 0x14, 0xB2, 0xCE, 0xA5, 0x30, 0x05, 0xDF};
    int sdHashKey3[] = {0x36, 0xA5, 0x3E, 0xAC, 0xC5, 0x26, 0x9E, 0xA3, 0x83, 0xD9, 0xEC, 0x25, 0x6C, 0x48, 0x48, 0x72};
    int sdHashKey4[] = {0xD8, 0xC0, 0xB0, 0xF3, 0x3E, 0x6B, 0x76, 0x85, 0xFD, 0xFB, 0x4D, 0x7D, 0x45, 0x1E, 0x92, 0x03};
    int sdHashKey5[] = {0xCB, 0x15, 0xF4, 0x07, 0xF9, 0x6A, 0x52, 0x3C, 0x04, 0xB9, 0xB2, 0xEE, 0x5C, 0x53, 0xFA, 0x86};
    int sdHashKey6[] = {0x70, 0x44, 0xA3, 0xAE, 0xEF, 0x5D, 0xA5, 0xF2, 0x85, 0x7F, 0xF2, 0xD6, 0x94, 0xF5, 0x36, 0x3B};
    int sdHashKey7[] = {0xEC, 0x6D, 0x29, 0x59, 0x26, 0x35, 0xA5, 0x7F, 0x97, 0x2A, 0x0D, 0xBC, 0xA3, 0x26, 0x33, 0x00};

typedef struct{
		int mode;
		byte key[16];
		byte pad[16];
		unsigned int padSize;
} _SD_Ctx1, *SD_Ctx1;

typedef struct{
		int mode;
		int unk;
		byte buf[16];
} _SD_Ctx2, *SD_Ctx2;

bool isNullKey(byte* key) {
	if (key != NULL) {
		int i=0;
		for (; i < 0x10; i++) {
			if (key[i] != (byte) 0) {
				return false;
			}
		}
	}
	return true;
}
    
void xorHash(byte* dest, int dest_offset, int* src, int src_offset, int size) {
	int i=0;
	for (int i = 0; i < size; i++) {
		dest[dest_offset + i] = (byte) (dest[dest_offset + i] ^ src[src_offset + i]);
	}
}
    
void xorKey(byte* dest, int dest_offset, byte* src, int src_offset, int size) {
	int i=0;
	for (int i = 0; i < size; i++) {
		dest[dest_offset + i] = (byte) (dest[dest_offset + i] ^ src[src_offset + i]);
	}
}

    void ScrambleSD(byte *buf, int size, int seed, int cbc, int kirk_code) {
        // Set CBC mode.
		*(int*)(buf)=cbc;
/*
        buf[0] = 0;
        buf[1] = 0;
        buf[2] = 0;
        buf[3] = (byte) cbc;
*/

        // Set unkown parameters to 0.
        buf[4] = 0;
        buf[5] = 0;
        buf[6] = 0;
        buf[7] = 0;

        buf[8] = 0;
        buf[9] = 0;
        buf[10] = 0;
        buf[11] = 0;

        // Set the the key seed to seed.
		*(int*)(buf+12)=seed;
/*
        buf[12] = 0;
        buf[13] = 0;
        buf[14] = 0;
        buf[15] = (byte) seed;
*/

        // Set the the data size to size.
		*(int*)(buf+16)=size;
/*
        buf[16] = (byte) ((size >> 24) & 0xFF);
        buf[17] = (byte) ((size >> 16) & 0xFF);
        buf[18] = (byte) ((size >> 8) & 0xFF);
        buf[19] = (byte) (size & 0xFF);
*/

        sceUtilsBufferCopyWithRange(buf, size, buf, size, kirk_code);
    }

    int getModeSeed(int mode) {
        int seed;
        switch (mode) {
            case 0x6:
                seed = 0x11;
                break;
            case 0x4:
                seed = 0xD;
                break;
            case 0x2:
                seed = 0x5;
                break;
            case 0x1:
                seed = 0x3;
                break;
            case 0x3:
                seed = 0xC;
                break;
            default:
                seed = 0x10;
                break;
        }
        return seed;
    }

    void cryptMember(SD_Ctx2 ctx, byte* data, int data_offset, int length) {
        int finalSeed;
        byte dataBuf[length + 0x14];memset(dataBuf,0,sizeof(dataBuf));
        byte keyBuf[0x10 + 0x10];memset(keyBuf,0,sizeof(keyBuf));
        byte hashBuf[0x10];memset(hashBuf,0,sizeof(hashBuf));

        // Copy the hash stored by hleSdCreateList.
        arraycopy(ctx->buf, 0, dataBuf, 0x14, 0x10);

        if (ctx->mode == 0x1) {
            // Decryption mode 0x01: decrypt the hash directly with KIRK CMD7.
            ScrambleSD(dataBuf, 0x10, 0x4, 5, 0x07);
            finalSeed = 0x53;
        } else if (ctx->mode == 0x2) {
            // Decryption mode 0x02: decrypt the hash directly with KIRK CMD8.
            ScrambleSD(dataBuf, 0x10, 0x100, 5, 0x08);
            finalSeed = 0x53;
        } else if (ctx->mode == 0x3) {
            // Decryption mode 0x03: XOR the hash with SD keys and decrypt with KIRK CMD7.
            xorHash(dataBuf, 0x14, sdHashKey4, 0, 0x10);
            ScrambleSD(dataBuf, 0x10, 0xE, 5, 0x07);
            xorHash(dataBuf, 0, sdHashKey3, 0, 0x10);
            finalSeed = 0x57;
        } else if (ctx->mode == 0x4) {
            // Decryption mode 0x04: XOR the hash with SD keys and decrypt with KIRK CMD8.
            xorHash(dataBuf, 0x14, sdHashKey4, 0, 0x10);
            ScrambleSD(dataBuf, 0x10, 0x100, 5, 0x08);
            xorHash(dataBuf, 0, sdHashKey3, 0, 0x10);
            finalSeed = 0x57;
        } else if (ctx->mode == 0x6) {
            // Decryption mode 0x06: XOR the hash with new SD keys and decrypt with KIRK CMD8.
            xorHash(dataBuf, 0x14, sdHashKey7, 0, 0x10);
            ScrambleSD(dataBuf, 0x10, 0x100, 5, 0x08);
            xorHash(dataBuf, 0, sdHashKey6, 0, 0x10);
            finalSeed = 0x64;
        } else {
            // Decryption mode 0x05: XOR the hash with new SD keys and decrypt with KIRK CMD7.
            xorHash(dataBuf, 0x14, sdHashKey7, 0, 0x10);
            ScrambleSD(dataBuf, 0x10, 0x12, 5, 0x07);
            xorHash(dataBuf, 0, sdHashKey6, 0, 0x10);
            finalSeed = 0x64;
        }

        // Store the calculated key.
		arraycopy(dataBuf, 0, keyBuf, 0x10, 0x10);

        // Apply extra padding if ctx.unk is not 1.
        if (ctx->unk != 0x1) {
            arraycopy(keyBuf, 0x10, keyBuf, 0, 0xC);
            keyBuf[0xC] = (byte) ((ctx->unk - 1) & 0xFF);
            keyBuf[0xD] = (byte) (((ctx->unk - 1) >> 8) & 0xFF);
            keyBuf[0xE] = (byte) (((ctx->unk - 1) >> 16) & 0xFF);
            keyBuf[0xF] = (byte) (((ctx->unk - 1) >> 24) & 0xFF);
        }

        // Copy the first 0xC bytes of the obtained key and replicate them
        // across a new list buffer. As a terminator, add the ctx1.seed parameter's
        // 4 bytes (endian swapped) to achieve a full numbered list.
        for (int i = 0x14; i < (length + 0x14); i += 0x10) {
            arraycopy(keyBuf, 0x10, dataBuf, i, 0xC);
            dataBuf[i + 0xC] = (byte) (ctx->unk & 0xFF);
            dataBuf[i + 0xD] = (byte) ((ctx->unk >> 8) & 0xFF);
            dataBuf[i + 0xE] = (byte) ((ctx->unk >> 16) & 0xFF);
            dataBuf[i + 0xF] = (byte) ((ctx->unk >> 24) & 0xFF);
            ctx->unk++;
        }

        arraycopy(dataBuf, length + 0x04, hashBuf, 0, 0x10);

        ScrambleSD(dataBuf, length, finalSeed, 5, 0x07);

        // XOR the first 16-bytes of data with the saved key to generate a new hash.
        xorKey(dataBuf, 0, keyBuf, 0, 0x10);

        // Copy back the last hash from the list to the first half of keyBuf.
        arraycopy(hashBuf, 0, keyBuf, 0, 0x10);

        // Finally, XOR the full list with the given data.
        xorKey(data, data_offset, dataBuf, 0, length);
    }


    /*
     * sceSd - chnnlsv.prx
     */
    int hleSdSetIndex(SD_Ctx1 ctx, int encMode) {
        // Set all parameters to 0 and assign the encMode.
        ctx->mode = encMode;
        return 0;
    }

    int hleSdCreateList(SD_Ctx2 ctx, int encMode, int genMode, byte* data, byte* key) {
        // If the key is not a 16-byte key, return an error.
        //if (key.length < 0x10) {
        //    return -1;
        //}

        // Set the mode and the unknown parameters.
        ctx->mode = encMode;
        ctx->unk = 0x1;

        // Key generator mode 0x1 (encryption): use an encrypted pseudo random number before XORing the data with the given key.
        if (genMode == 0x1) {
            byte header[0x25];
            byte seed[0x14];

            // Generate SHA-1 to act as seed for encryption.
            //ByteBuffer bSeed = ByteBuffer.wrap(seed);
            sceUtilsBufferCopyWithRange(seed, 0x14, NULL, 0, 0xE);
                       
            // Propagate SHA-1 in kirk header.
            arraycopy(seed, 0, header, 0, 0x10);
            arraycopy(seed, 0, header, 0x14, 0x10);

            // Encryption mode 0x1: encrypt with KIRK CMD4 and XOR with the given key.
            if (ctx->mode == 0x1) {
                ScrambleSD(header, 0x10, 0x4, 0x4, 0x04);
                arraycopy(header, 0, ctx->buf, 0, 0x10);
                arraycopy(header, 0, data, 0, 0x10);
                // If the key is not null, XOR the hash with it.
                if (!isNullKey(key)) {
                    xorKey(ctx->buf, 0, key, 0, 0x10);
                }
                return 0;
            } else if (ctx->mode == 0x2) { // Encryption mode 0x2: encrypt with KIRK CMD5 and XOR with the given key.
                ScrambleSD(header, 0x10, 0x100, 0x4, 0x05);
                arraycopy(header, 0, ctx->buf, 0, 0x10);
                arraycopy(header, 0, data, 0, 0x10);
                // If the key is not null, XOR the hash with it.
                if (!isNullKey(key)) {
                    xorKey(ctx->buf, 0, key, 0, 0x10);
                }
                return 0;
            } else if (ctx->mode == 0x3) { // Encryption mode 0x3: XOR with SD keys, encrypt with KIRK CMD4 and XOR with the given key.
                xorHash(header, 0x14, sdHashKey3, 0, 0x10);
                ScrambleSD(header, 0x10, 0xE, 0x4, 0x04);
                xorHash(header, 0, sdHashKey4, 0, 0x10);
                arraycopy(header, 0, ctx->buf, 0, 0x10);
                arraycopy(header, 0, data, 0, 0x10);
                // If the key is not null, XOR the hash with it.
                if (!isNullKey(key)) {
                    xorKey(ctx->buf, 0, key, 0, 0x10);
                }
                return 0;
            } else if (ctx->mode == 0x4) { // Encryption mode 0x4: XOR with SD keys, encrypt with KIRK CMD5 and XOR with the given key.
                xorHash(header, 0x14, sdHashKey3, 0, 0x10);
                ScrambleSD(header, 0x10, 0x100, 0x4, 0x05);
                xorHash(header, 0, sdHashKey4, 0, 0x10);
                arraycopy(header, 0, ctx->buf, 0, 0x10);
                arraycopy(header, 0, data, 0, 0x10);
                // If the key is not null, XOR the hash with it.
                if (!isNullKey(key)) {
                    xorKey(ctx->buf, 0, key, 0, 0x10);
                }
                return 0;
            } else if (ctx->mode == 0x6) { // Encryption mode 0x6: XOR with new SD keys, encrypt with KIRK CMD5 and XOR with the given key.
                xorHash(header, 0x14, sdHashKey6, 0, 0x10);
                ScrambleSD(header, 0x10, 0x100, 0x4, 0x05);
                xorHash(header, 0, sdHashKey7, 0, 0x10);
                arraycopy(header, 0, ctx->buf, 0, 0x10);
                arraycopy(header, 0, data, 0, 0x10);
                // If the key is not null, XOR the hash with it.
                if (!isNullKey(key)) {
                    xorKey(ctx->buf, 0, key, 0, 0x10);
                }
                return 0;
            } else { // Encryption mode 0x5: XOR with new SD keys, encrypt with KIRK CMD4 and XOR with the given key.
                xorHash(header, 0x14, sdHashKey6, 0, 0x10);
                ScrambleSD(header, 0x10, 0x12, 0x4, 0x04);
                xorHash(header, 0, sdHashKey7, 0, 0x10);
                arraycopy(header, 0, ctx->buf, 0, 0x10);
                arraycopy(header, 0, data, 0, 0x10);
                // If the key is not null, XOR the hash with it.
                if (!isNullKey(key)) {
                    xorKey(ctx->buf, 0, key, 0, 0x10);
                }
                return 0;
            }
        } else if (genMode == 0x2) { // Key generator mode 0x02 (decryption): directly XOR the data with the given key.
            // Grab the data hash (first 16-bytes).
            arraycopy(data, 0, ctx->buf, 0, 0x10);
            // If the key is not null, XOR the hash with it.
            if (!isNullKey(key)) {
                xorKey(ctx->buf, 0, key, 0, 0x10);
            }
            return 0;
        } else {
            // Invalid mode.
            return -1;
        }
    }

    int hleSdRemoveValue(SD_Ctx1 ctx, byte *data, int length) {
	int i;
        if (ctx->padSize > 0x10 || (length < 0)) {
            // Invalid key or length.
            return -1;
        } else if (((ctx->padSize + length) <= 0x10)) {
            // The key hasn't been set yet.
            // Extract the hash from the data and set it as the key.
            arraycopy(data, 0, ctx->pad, ctx->padSize, length);
            ctx->padSize += length;
            return 0;
        } else {
            // Calculate the seed.
            int seed = getModeSeed(ctx->mode);

            // Setup the buffers. 
            byte scrambleBuf[(length + ctx->padSize) + 0x14];

            // Copy the previous key to the buffer.
            arraycopy(ctx->pad, 0, scrambleBuf, 0x14, ctx->padSize);

            // Calculate new key length.
            int kLen = ctx->padSize;

            ctx->padSize += length;
            ctx->padSize &= 0x0F;
            if (ctx->padSize == 0) {
                ctx->padSize = 0x10;
            }

            // Calculate new data length.
            length -= ctx->padSize;

            // Copy data's footer to make a new key.
            arraycopy(data, length, ctx->pad, 0, ctx->padSize);

            // Process the encryption in 0x800 blocks.
            int blockSize = 0;
            int dataOffset = 0;

            while (length > 0) {
                blockSize = (length + kLen >= 0x800) ? 0x800 : length + kLen;

                arraycopy(data, dataOffset, scrambleBuf, 0x14 + kLen, blockSize - kLen);

                // Encrypt with KIRK CMD 4 and XOR with result.
                xorKey(scrambleBuf, 0x14, ctx->key, 0, 0x10);
                ScrambleSD(scrambleBuf, blockSize, seed, 0x4, 0x04);
                arraycopy(scrambleBuf, (blockSize + 0x4) - 0x14, ctx->key, 0, 0x10);

                // Adjust data length, data offset and reset any key length.
                length -= (blockSize - kLen);
                dataOffset += (blockSize - kLen);
                kLen = 0;
            }

            return 0;
        }
    }

    int hleSdGetLastIndex(SD_Ctx1 ctx, byte *hash, byte *key) {
	int i;
        if (ctx->padSize > 0x10) {
            // Invalid key length.
            return -1;
        }

        // Setup the buffers.           
        byte scrambleEmptyBuf[0x10 + 0x14];memset(scrambleEmptyBuf,0,sizeof(scrambleEmptyBuf));
        byte keyBuf[0x10];memset(keyBuf,0,sizeof(keyBuf));
        byte scrambleKeyBuf[0x10 + 0x14];memset(scrambleKeyBuf,0,sizeof(scrambleKeyBuf));
        byte resultBuf[0x10];memset(resultBuf,0,sizeof(resultBuf));
        byte scrambleResultBuf[0x10 + 0x14];memset(scrambleResultBuf,0,sizeof(scrambleResultBuf));
        byte scrambleResultKeyBuf[0x10 + 0x14];memset(scrambleResultKeyBuf,0,sizeof(scrambleResultKeyBuf));

        // Calculate the seed.
        int seed = getModeSeed(ctx->mode);

        // Encrypt an empty buffer with KIRK CMD 4.
        ScrambleSD(scrambleEmptyBuf, 0x10, seed, 0x4, 0x04);
        arraycopy(scrambleEmptyBuf, 0, keyBuf, 0, 0x10);

        // Apply custom padding management.
        byte b = ((keyBuf[0] & (byte) 0x80) != 0) ? (byte) 0x87 : 0;
        for (i = 0; i < 0xF; i++) {
            keyBuf[i] = (byte) ((keyBuf[i] << 1) | ((keyBuf[i + 1] >> 7) & 0x01));
        }
        keyBuf[0xF] = (byte) ((keyBuf[0xF] << 1) ^ b);

        if (ctx->padSize < 0x10) {
            byte bb = ((keyBuf[0] & (byte) 0x80) != 0) ? (byte) 0x87 : 0;
            for (i = 0; i < 0xF; i++) {
                keyBuf[i] = (byte) ((keyBuf[i] << 1) | ((keyBuf[i + 1] >> 7) & 0x01));
            }
            keyBuf[0xF] = (byte) ((keyBuf[0xF] << 1) ^ bb);

            ctx->pad[ctx->padSize] = (byte) 0x80;
            if ((ctx->padSize + 1) < 0x10) {
                for (i = 0; i < (0x10 - ctx->padSize - 1); i++) {
                    ctx->pad[ctx->padSize + 1 + i] = 0;
                }
            }
        }

        // XOR previous key with new one.
        xorKey(ctx->pad, 0, keyBuf, 0, 0x10);

        arraycopy(ctx->pad, 0, scrambleKeyBuf, 0x14, 0x10);
        arraycopy(ctx->key, 0, resultBuf, 0, 0x10);

        // Encrypt with KIRK CMD 4 and XOR with result.
        xorKey(scrambleKeyBuf, 0x14, resultBuf, 0, 0x10);
        ScrambleSD(scrambleKeyBuf, 0x10, seed, 0x4, 0x04);
        arraycopy(scrambleKeyBuf, (0x10 + 0x4) - 0x14, resultBuf, 0, 0x10);

        // If ctx.mode is new mode 0x5 or 0x6, XOR with the new hash key 5, else, XOR with hash key 2.
        if ((ctx->mode == 0x5) || (ctx->mode == 0x6)) {
            xorHash(resultBuf, 0, sdHashKey5, 0, 0x10);
        } else if ((ctx->mode == 0x3) || (ctx->mode == 0x4)) {
            xorHash(resultBuf, 0, sdHashKey2, 0, 0x10);
        }

        // If mode is 2, 4 or 6, encrypt again with KIRK CMD 5 and then KIRK CMD 4.
        if ((ctx->mode == 0x2) || (ctx->mode == 0x4) || (ctx->mode == 0x6)) {
            arraycopy(resultBuf, 0, scrambleResultBuf, 0x14, 0x10);
            ScrambleSD(scrambleResultBuf, 0x10, 0x100, 0x4, 0x05);
            arraycopy(scrambleResultBuf, 0, scrambleResultBuf, 0x14, 0x10);
            for(int i = 0; i < 0x14; i++) {
                scrambleResultBuf[i] = 0;
            }
            ScrambleSD(scrambleResultBuf, 0x10, seed, 0x4, 0x04);
            arraycopy(scrambleResultBuf, 0, resultBuf, 0, 0x10);
        }

        // XOR with the supplied key and encrypt with KIRK CMD 4.
        if (key != NULL) {
            xorKey(resultBuf, 0, key, 0, 0x10);
            arraycopy(resultBuf, 0, scrambleResultKeyBuf, 0x14, 0x10);
            ScrambleSD(scrambleResultKeyBuf, 0x10, seed, 0x4, 0x04);
            arraycopy(scrambleResultKeyBuf, 0, resultBuf, 0, 0x10);
        }

        // Copy back the generated hash.
        arraycopy(resultBuf, 0, hash, 0, 0x10);

        // Clear the context fields.
		memset(ctx,0,sizeof(_SD_Ctx1));

        return 0;
    }

    int hleSdSetMember(SD_Ctx2 ctx, byte* data, int length) {
        if (length <= 0) {
            return -1;
        }

        // Parse the data in 0x800 blocks first.
        int index = 0;
        if (length >= 0x800) {
            for (index = 0; length >= 0x800; index += 0x800) {
                cryptMember(ctx, data, index, 0x800);
                length -= 0x800;
            }
        }

        // Finally parse the rest of the data.
        cryptMember(ctx, data, index, length);

        return 0;
    }

    void DecryptSavedata(byte *buf, int size, byte *key) {
        // Initialize the context structs.
        int sdDecMode;
        _SD_Ctx1 ctx1;memset(&ctx1,0,sizeof(ctx1));
        _SD_Ctx2 ctx2;memset(&ctx2,0,sizeof(ctx2));

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
            //    sdDecMode = 3;
            //}
        }

        // Perform the decryption.
        hleSdSetIndex(&ctx1, sdDecMode);
        hleSdCreateList(&ctx2, sdDecMode, 2, buf, key);
        hleSdRemoveValue(&ctx1, buf, 0x10);
        
        arraycopy(buf, 0x10, tmpbuf, 0, size - 0x10);
        hleSdRemoveValue(&ctx1, tmpbuf, alignedSize);
        
        hleSdSetMember(&ctx2, tmpbuf, alignedSize);
        
        // Clear context 2.
        hleChnnlsv_21BE78B4(&ctx2);
        
        // Generate a file hash for this data.
        //hleSdGetLastIndex(&ctx1, hash, key);
        
        // Copy back the data.
        arraycopy(tmpbuf, 0, buf, 0, size - 0x10);

        //return hash;
    }

    void EncryptSavedata(byte* buf, int size, byte *key, byte *hash) {
        // Initialize the context structs.
        int sdEncMode;
        _SD_Ctx1 ctx1;memset(&ctx1,0,sizeof(ctx1));
        _SD_Ctx2 ctx2;memset(&ctx2,0,sizeof(ctx2));

        // Setup the buffers.
        int alignedSize = ((size + 0xF) >> 4) << 4;
        byte tmpbuf1[alignedSize + 0x10];memset(tmpbuf1,0,sizeof(tmpbuf1));
        byte tmpbuf2[alignedSize];memset(tmpbuf2,0,sizeof(tmpbuf2));

        // Copy the plain data to tmpbuf.
        arraycopy(buf, 0, tmpbuf1, 0x10, size);

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
        hleSdCreateList(&ctx2, sdEncMode, 1, tmpbuf1, key);
        hleSdSetIndex(&ctx1, sdEncMode);
        hleSdRemoveValue(&ctx1, tmpbuf1, 0x10);
        
        arraycopy(tmpbuf1, 0x10, tmpbuf2, 0, alignedSize);
        hleSdSetMember(&ctx2, tmpbuf2, alignedSize);
        
        // Clear extra bytes.
		int i;
        for (i = 0; i < (alignedSize - size); i++) {
            tmpbuf2[size + i] = 0;
        }
        
        // Encrypt the data.
        hleSdRemoveValue(&ctx1, tmpbuf2, alignedSize);
        
        // Copy back the encrypted data + IV.
        arraycopy(tmpbuf2, 0, tmpbuf1, 0x10, alignedSize);
        arraycopy(tmpbuf1, 0, buf, 0, size+0x10);
        
        // Clear context 2.
        hleChnnlsv_21BE78B4(&ctx2);
        
        // Generate a file hash for this data.
        hleSdGetLastIndex(&ctx1, hash, key);

        //return hash;
    }

    void GenerateSavedataHash(byte *data, int size, int mode, byte* key, byte *hash) {
        _SD_Ctx1 ctx1;memset(&ctx1,0,sizeof(ctx1));

        // Generate a new hash using a key.
        hleSdSetIndex(&ctx1, mode);
        hleSdRemoveValue(&ctx1, data, size);
        if(hleSdGetLastIndex(&ctx1, hash, NULL)<0)memset(hash,1,0x10);
        
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
		if((mode&0x4)==0x4)mode=2;

        if ((mode & 0x4) == 0x4) {
            // Generate a type 6 hash.
            GenerateSavedataHash(data, size, 6, key, savedataParams+0x20);
			savedataParams[0]|=0x01;

            savedataParams[0]|=0x40;
			// Generate a type 5 hash.
			GenerateSavedataHash(data, size, 5, key, savedataParams+0x70);
            //savedataParams[0] |= 0x40;
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
			"ported by popsdeco\n"
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
	char *inbuf=calloc(size+0x10,1);
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
			char *p=malloc(sfosize);
			fread(p,1,sfosize,f);
			if(memcmp(p,"\0PSF",4)||read32(p+4)!=0x00000101)return 1;

			int label_offset=read32(p+8);
			int data_offset=read32(p+12);
			int nlabel=read32(p+16);
			int i=0,j=0;
			for(;i<nlabel;i++){
				if(!strcmp(p+label_offset+read16(p+20+16*i),"SAVEDATA_PARAMS")){
					for(;j<nlabel;j++){
						if(!strcmp(p+label_offset+read16(p+20+16*j),"SAVEDATA_FILE_LIST")){
							int paramsize=read32(p+20+16*i+8);
							u8 *param=p+data_offset+read32(p+20+16*i+12);
#ifdef HASHTEST
							fwrite(param,1,paramsize,stdout); ///
							UpdateSavedataHashes(param,p,sfosize);
							fwrite(param,1,paramsize,stdout);

							fseek(f,data_offset+read32(p+20+16*i+12),SEEK_SET);
							fwrite(p+data_offset+read32(p+20+16*i+12),1,paramsize,f);
#else
							EncryptSavedata(inbuf, size, key, p+data_offset+read32(p+20+16*j+12)+0x0d);
							fwrite(inbuf,1,size+0x10,stdout);
							UpdateSavedataHashes(param,p,sfosize);
							//DecryptSavedata(inbuf, size+0x10, key);
							//fwrite(inbuf,1,size,stdout);

							//write back
							fseek(f,data_offset+read32(p+20+16*i+12),SEEK_SET);
							fwrite(p+data_offset+read32(p+20+16*i+12),1,paramsize,f);
							fseek(f,data_offset+read32(p+20+16*j+12)+0x0d,SEEK_SET);
							fwrite(p+data_offset+read32(p+20+16*j+12)+0x0d,1,0x10,f);
#endif
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