#include <stdio.h>
#include "Kasumi.h"

int main(void) {
	int i;

	//u8 key[16] = "\x99\x00\xaa\xbb\xcc\xdd\xee\xff\x11\x22\x33\x44\x55\x66\x77\x88";
	//u8 text[8] = "\xfe\xdc\xba\x09\x87\x65\x43\x21";
	//u8 text[8] = "\x61\x61\x61\x61\x61\x61\x61\x61";

	u8 key[16] = {
        0x99, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 
    };
    u8 text[8]  = {
        //0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x09, 0x87, 0x65, 0x43, 0x21,
        //0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
    };

    printf("Key:\t\t");
	for(i = 0; i < 16; i++)
	    printf("%02x ", key[i]);
	printf("\n");

	printf("Input:\t\t");
	for(i = 0; i < 8; i++)
	    printf("%02x ", text[i]);
	printf("\n");

	KeySchedule(key);
	Kasumi(text);

	printf("Encrypted:\t");
	for (i = 0; i < 8; i++)
        printf("%02x ", text[i]);
    printf("\n");

    KasumiDecipher(text);

    printf("Decrypted:\t");
	for (i = 0; i < 8; i++)
        printf("%02x ", text[i]);
    printf("\n");
}


/*

Input:		fe dc ba 09 87 65 43 21 
Encrypted:	d8 63 ca a1 87 65 43 21 
			51 48 96 22 6c aa 4f 20 

Input:		fe dc ba 09 87 65 43 21 
Encrypted:	51 48 96 22 6c aa 4f 20 


encrypted 0x514896226caa4f20
decrypted 0xfedcba0987654321

*/
