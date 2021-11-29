/*-------------------------------------------------------------------------------------------
 *										Sandwich.c
 *-------------------------------------------------------------------------------------------
 *
 * An implementation of sandwich attack presented by Dunkelman et al.
 *
 *-------------------------------------------------------------------------------------------*/

#include <stdio.h>      // printf()
#include <stdlib.h>		// rand(), srand()
#include <time.h>    	// time()
#include <math.h>       // pow()
#include "uthash.h"
#include "Kasumi.h"

static u8 *Ka;
static u8 Kb[16], Kc[16], Kd[16];

static void printHex(char name[], u8 text[], int n) {
	printf("%s:\t", name);
	for (int i = 0; i < n; i++)
        printf("%02x ", text[i]);
    printf("\n");
}

/*-------------------------------------------------------------------------------------------
 * Let ΔK_ab = (0, 0, 8000_x , 0, 0, 0, 0, 0) and ΔK_ac = (0, 0, 0, 0, 0, 0, 8000_x , 0), and
 * let K_a , K_b = K_a xor ΔK_ab , K_c = K_a xor ΔK_ac , and K_d = K_c xor ΔK_ab be the
 * unknown related keys we wish to retrieve.
 *-------------------------------------------------------------------------------------------*/

static void generateRelatedKeys(u8 Ka[]) {
    for (int i = 0; i < 16; i++) {
    	if (i == 4)
    		Kb[i] = Ka[i] ^ 0x80;
    	else 
    		Kb[i] = Ka[i];		
    }

    for (int i = 0; i < 16; i++) {
    	if (i == 12)
    		Kc[i] = Ka[i] ^ 0x80;
    	else 
    		Kc[i] = Ka[i];		
    }

    for (int i = 0; i < 16; i++) {
    	if (i == 4)
    		Kd[i] = Kc[i] ^ 0x80;
    	else 
    		Kd[i] = Kc[i];		
    }
}

int main(void) {
	time_t t;

	// Hardcoded key Ka
	Ka = (u8 [16]) {
        0x99, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 
    };

    generateRelatedKeys(Ka);

    printHex("Ka", Ka, 16);
    printHex("Kb", Kb, 16);
    printHex("Kc", Kc, 16);
    printHex("Kd", Kd, 16);

    /*-------------------------------------------------------------------------------------------
	 * 1. Data Collection Phase:
	 *-------------------------------------------------------------------------------------------*/

    /*-------------------------------------------------------------------------------------------
	 *	(a) Choose a structure of 2^24 ciphertexts of the form C_a = (X_a, A), where
	 *		A is ﬁxed and X a assumes 2^24 arbitrary diﬀerent values. 
	 *-------------------------------------------------------------------------------------------*/

	/* Intializes random number generator */
	srand((unsigned) time(&t));

	u8 Ca[8];
    u8 A[4] = {
        0xff, 0xff, 0xff, 0xff,
    };
    for (int i = 0; i < 4; i++) {
        //Ca[i] = rand() % 255;     // 255_10 = ff_16 = 11111111_2
        Ca[i] = 0x11;
    }
    for (int i = 0; i < 4; i++) {
        Ca[4+i] = A[i];
    }

    printHex("Ca", Ca, 8);

    /*-------------------------------------------------------------------------------------------
	 *		Ask for the decryption of all the ciphertexts under the key K_a and denote the plain-
	 * 		text corresponding to C_a by P_a.
	 *-------------------------------------------------------------------------------------------*/

    KeySchedule(Ka);
    KasumiDecipher(Ca);

    printHex("Pa", Ca, 8);

    /*-------------------------------------------------------------------------------------------
	 *		For each P_a, ask for the encryption of P_b = P_a xor (0_x, 0010 0000_x) 
	 *		under the key K_b and denote the resulting ciphertext by C_b.
	 *-------------------------------------------------------------------------------------------*/

    u8 Pb[8];
    for (int i = 0; i < 8; i++) {
        if (i != 5)
    	    Pb[i] = Ca[i];
        else 
            Pb[i] = Ca[i] ^ 0x10;
    }

    printHex("Pb", Pb, 8);

    KeySchedule(Kb);
    Kasumi(Pb);

    printHex("Cb", Pb, 8);

    /*-------------------------------------------------------------------------------------------
     *      TODO: Store the pairs (C_a , C_b ) in a hash table indexed by the
     *      32-bit value C_b^R (i.e., the right half of C_b ).
     *-------------------------------------------------------------------------------------------*/

    /*-------------------------------------------------------------------------------------------
	 *	(b) Choose a structure of 2^24 ciphertexts of the form C_c = (Y_c , A xor 0010 0000_x ),
	 *		where A is the same constant as before, and Y_c assumes 2^24 arbitrary dif-
	 *		ferent values. 
	 *-------------------------------------------------------------------------------------------*/

    u8 Cc[8];
    for (int i = 0; i < 4; i++) {
        //Ca[i] = rand() % 255;     // 255_10 = ff_16 = 11111111_2
        Cc[i] = 0xaa;
    }
    for (int i = 0; i < 4; i++) {
        if (i != 1)
            Cc[4+i] = A[i];
        else
            Cc  [4+i] = A[i] ^ 0x10;
    }

    printHex("Cc", Cc, 8);    

    /*-------------------------------------------------------------------------------------------
	 *		Ask for the decryption of the ciphertexts under the key K_c
	 * 		and denote the plaintext corresponding to C_c by P_c. 
	 *-------------------------------------------------------------------------------------------*/

    KeySchedule(Kc);
    KasumiDecipher(Cc);

    printHex("Pc", Cc, 8);

    /*-------------------------------------------------------------------------------------------
	 *		For each P_c , ask for the encryption of P_d = P_c xor (0_x , 0010 0000_x)
	 *		under the key K_d and denote the resulting ciphertext by C_d .
	 *-------------------------------------------------------------------------------------------*/

    u8 Pd[8];
    for (int i = 0; i < 8; i++) {
        if (i != 5)
            Pd[i] = Cc[i];
        else
            Pd[i] = Cc[i] ^ 0x10;
    }

    printHex("Pd", Pd, 8);

    KeySchedule(Kd);
    Kasumi(Pd);

    printHex("Cd", Pd, 8);

    /*-------------------------------------------------------------------------------------------
     *      TODO: Then, access the hash table in the entry
     *      corresponding to the value C d R ⊕ 0010 0000 x , and for each pair (C a , C b )
     *      found in this entry, apply Step 2 on the quartet (C a , C b , C c , C d ).
     *-------------------------------------------------------------------------------------------*/
}