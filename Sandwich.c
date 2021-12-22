/*-------------------------------------------------------------------------------------------
 *										Sandwich.c
 *-------------------------------------------------------------------------------------------
 *
 * An implementation of sandwich attack presented by Dunkelman et al.
 *
 *-------------------------------------------------------------------------------------------*/

#include <stdio.h>         	// printf()
#include <stdlib.h>			// rand(), srand()
#include <time.h>    	   	// time()
#include <math.h>          	// pow()
#include <sys/resource.h>
#include "uthash.h"
#include "Kasumi.h"


/*---------------------------------------- UTILITY ------------------------------------------*/

struct rusage usage;

static void printHex(char name[], u8 text[], int n) {
	printf("%s:\t", name);
	for (int i = 0; i < n; i++)
		printf("%02x ", text[i]);
	printf("\n");
}

#define PBSTR "||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||"
#define PBWIDTH 60

void printProgress(double percentage) {
	int val = (int) (percentage * 100);
	int lpad = (int) (percentage * PBWIDTH);
	int rpad = PBWIDTH - lpad;
	printf("\r%3d%% [%.*s%*s]", val, lpad, PBSTR, rpad, "");
	fflush(stdout);
}

/*----------------------------------------- KEYS --------------------------------------------*/

static u8 *Ka;
static u8 Kb[16], Kc[16], Kd[16];

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

/*--------------------------------------- HASHTABLE -----------------------------------------*/

/*------------------------------------ Data Collection --------------------------------------*/

struct dataCollectionEntry {
	u8 index[4];            // key:     (C_b^R)     8 Byte  
	u8 CaCb[16];            // value:   (C_a, C_b)                          16 Byte
	UT_hash_handle hh;      // makes this structure hashable                56 Byte
};

struct dataCollectionEntry *dataCollectionTable = NULL;

void addDataCollectionEntry(u8 index[], u8 Ca[], u8 Cb[]) {
	struct dataCollectionEntry *h;

	h = malloc(sizeof(struct dataCollectionEntry));

	for (int i = 0; i < 8; i++) {
		if (i < 4)
			h -> index[i] = index[i];
		h -> CaCb[i] = Ca[i];
		h -> CaCb[i + 8] = Cb[i];
	}

	unsigned keylen = (unsigned)sizeof((h)->index);  
	HASH_ADD(hh, dataCollectionTable, index[0], keylen, h);
}

struct dataCollectionEntry *findDataCollectionEntry(u8 index[]) {
	struct dataCollectionEntry *h;

	unsigned keylen = (unsigned)sizeof((h)->index);  
	HASH_FIND(hh, dataCollectionTable, index, keylen, h);         // h: output pointer

	return h;
}

void printDataCollectionEntries() {
	struct dataCollectionEntry *h;

	for(h = dataCollectionTable; h != NULL; h = (struct dataCollectionEntry*)(h -> hh.next)) {
		printHex("H_id", h -> index, 4);
		printHex("H_Ca", h -> CaCb, 8);
		printHex("H_Cb", h -> CaCb + 8, 8);
	}
}

void deleteAllDataCollectionEntries() {
	struct dataCollectionEntry *currentEntry, *tmp;

	HASH_ITER(hh, dataCollectionTable, currentEntry, tmp) {
    	HASH_DEL(dataCollectionTable, currentEntry);  			/* delete it (entries advances to next) */
    	free(currentEntry);             						/* free it */
    }
}

/*------------------------------------ Right Quartets ---------------------------------------*/

struct rightQuartetsEntry {
	u8 index[4];            // key:     (C_a^L XOR C_c^L)		    8 Byte  
	u8 CaCbCcCd[32];        // value:   (C_a, C_b, C_c, C_d)        32 Byte
	UT_hash_handle hh;      // makes this structure hashable        56 Byte
};

struct rightQuartetsEntry *rightQuartetsTable = NULL;

void addRightQuartetsEntry(u8 index[], u8 Ca[], u8 Cb[], u8 Cc[], u8 Cd[]) {
	struct rightQuartetsEntry *h;

	h = malloc(sizeof(struct rightQuartetsEntry));

	for (int i = 0; i < 8; i++) {
		if (i < 4)
			h -> index[i] = index[i];
		h -> CaCbCcCd[i] = Ca[i];
		h -> CaCbCcCd[i + 8] = Cb[i];
		h -> CaCbCcCd[i + 16] = Cc[i];
		h -> CaCbCcCd[i + 24] = Cd[i];
	}

	unsigned keylen = (unsigned)sizeof((h)->index);  
	HASH_ADD(hh, rightQuartetsTable, index[0], keylen, h);
}

struct rightQuartetsEntry *findRightQuartetsEntry(u8 index[]) {
	struct rightQuartetsEntry *h;

	unsigned keylen = (unsigned)sizeof((h)->index);  
	HASH_FIND(hh, rightQuartetsTable, index, keylen, h);         // h: output pointer

	return h;
}

void printRightQuartetsEntries() {
	struct rightQuartetsEntry *h;

	for(h = rightQuartetsTable; h != NULL; h = (struct rightQuartetsEntry*)(h -> hh.next)) {
		printHex("H_id", h -> index, 4);
		printHex("H_Ca", h -> CaCbCcCd, 8);
		printHex("H_Cb", h -> CaCbCcCd + 8, 8);
		printHex("H_Cc", h -> CaCbCcCd + 16, 8);
		printHex("H_Cd", h -> CaCbCcCd + 24, 8);
	}
}

void deleteAllRightQuartetsEntries() {
	struct rightQuartetsEntry *currentEntry, *tmp;

	HASH_ITER(hh, rightQuartetsTable, currentEntry, tmp) {
    	HASH_DEL(rightQuartetsTable, currentEntry);  			/* delete it (entries advances to next) */
    	free(currentEntry);             						/* free it */
    }
}

/*--------------------------------------- SANDWICH -----------------------------------------*/

int main(void) {
	clock_t begin = clock();
	time_t t;
	int exp = 24;
	int nPlaintext = pow(2, exp);       // should be pow(2, 24)

	// Hardcoded key Ka
	Ka = (u8 [16]) {
		0x99, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 
	};

	generateRelatedKeys(Ka);

	//printHex("Ka", Ka, 16);
	//printHex("Kb", Kb, 16);
	//printHex("Kc", Kc, 16);
	//printHex("Kd", Kd, 16);

	/*-------------------------------------------------------------------------------------------
	 * 1. Data Collection Phase:
	 *-------------------------------------------------------------------------------------------*/

	/*-------------------------------------------------------------------------------------------
	 *	(a) Choose a structure of 2^24 ciphertexts of the form C_a = (X_a, A), where
	 *		A is ﬁxed and X a assumes 2^24 arbitrary diﬀerent values. 
	 *-------------------------------------------------------------------------------------------*/

	srand((unsigned) time(&t));    // Initializes random number generator
	int z = 0;                     // Initializes the progress bar

	u8 Pa[8], Pb[8], Pc[8], Pd[8], Ca[8], Cb[8], Cc[8], Cd[8];
	u8 indexDC[4], indexRQ[4];
	u8 A[4] = {
		0xff, 0xff, 0xff, 0xff,
	};

	printf("Generating Ca, Pa, Pb and Cc...\n");

	for (int j = 0; j < nPlaintext; j++) {

		for (int i = 0; i < 4; i++) {
			Ca[i] = rand() % 255;     // 255_10 = ff_16 = 11111111_2
		}
		for (int i = 0; i < 4; i++) {
			Ca[4+i] = A[i];
		}

		//printHex("Ca", Ca, 8);

		/*-------------------------------------------------------------------------------------------
		 *		Ask for the decryption of all the ciphertexts under the key K_a and denote the plain-
		 * 		text corresponding to C_a by P_a.
		 *-------------------------------------------------------------------------------------------*/

		memcpy(Pa, &Ca[0], 8*sizeof(*Ca));
		KeySchedule(Ka);
		KasumiDecipher(Pa);

		//printHex("Pa", Pa, 8);

		/*-------------------------------------------------------------------------------------------
		 *		For each P_a, ask for the encryption of P_b = P_a xor (0_x, 0010 0000_x) 
		 *		under the key K_b and denote the resulting ciphertext by C_b.
		 *-------------------------------------------------------------------------------------------*/

		for (int i = 0; i < 8; i++) {
			if (i != 5)
				Pb[i] = Pa[i];
			else 
				Pb[i] = Pa[i] ^ 0x10;
		}

		//printHex("Pb", Pb, 8);

		memcpy(Cb, &Pb[0], 8*sizeof(*Pb));
		KeySchedule(Kb);
		Kasumi(Cb);

		//printHex("Cb", Cb, 8);

		/*-------------------------------------------------------------------------------------------
		 *      Store the pairs (C_a , C_b ) in a hash table indexed by the
		 *      32-bit value C_b^R (i.e., the right half of C_b ).
		 *-------------------------------------------------------------------------------------------*/

		memcpy(indexDC, &Cb[4], 4*sizeof(*Cb));
		//printHex("INDEX", indexDC, 4);

		addDataCollectionEntry(indexDC, Ca, Cb);
		//printEntries();

		if (j > z * (nPlaintext/100.0)) {
			printProgress(z/100.0);
			z++;
		} else if (j == nPlaintext - 1) 
			printProgress(1);
	}
	printf("\n");

	printf("Hash table overhead (GB): %.2f\n", HASH_OVERHEAD(hh, dataCollectionTable)/1000000000.0);

	/*-------------------------------------------------------------------------------------------
	 *	(b) Choose a structure of 2^24 ciphertexts of the form C_c = (Y_c , A xor 0010 0000_x ),
	 *		where A is the same constant as before, and Y_c assumes 2^24 arbitrary dif-
	 *		ferent values. 
	 *-------------------------------------------------------------------------------------------*/

	z = 1;

	printf("Generating Cc, Pc, Pd and Cd...\n");

	for (int j = 0; j < nPlaintext; j++) {
		for (int i = 0; i < 4; i++) {
			Cc[i] = rand() % 255;     // 255_10 = ff_16 = 11111111_2
			//Cc[i] = 0xaa;
		}
		for (int i = 0; i < 4; i++) {
			if (i != 1)
				Cc[4+i] = A[i];
			else
				Cc  [4+i] = A[i] ^ 0x10;
		}

		//printHex("Cc", Cc, 8);    

		/*-------------------------------------------------------------------------------------------
		 *		Ask for the decryption of the ciphertexts under the key K_c
		 * 		and denote the plaintext corresponding to C_c by P_c. 
		 *-------------------------------------------------------------------------------------------*/

		memcpy(Pc, &Cc[0], 8*sizeof(*Cc));
		KeySchedule(Kc);
		KasumiDecipher(Pc);

		//printHex("Pc", Pc, 8);

		/*-------------------------------------------------------------------------------------------
		 *		For each P_c , ask for the encryption of P_d = P_c xor (0_x , 0010 0000_x)
		 *		under the key K_d and denote the resulting ciphertext by C_d .
		 *-------------------------------------------------------------------------------------------*/

		for (int i = 0; i < 8; i++) {
			if (i != 5)
				Pd[i] = Pc[i];
			else
				Pd[i] = Pc[i] ^ 0x10;
		}

		//printHex("Pd", Pd, 8);

		memcpy(Cd, &Pd[0], 8*sizeof(*Pd));
		KeySchedule(Kd);
		Kasumi(Cd);

		//printHex("Cd", Cd, 8);

		/*-------------------------------------------------------------------------------------------
		 *      Then, access the hash table in the entry
		 *      corresponding to the value C_d^R ⊕ 00100000_x , and for each pair (C_a, C_b)
		 *      found in this entry, apply Step 2 on the quartet (C_a, C_b, C_c, C_d).
		 *-------------------------------------------------------------------------------------------*/

		memcpy(indexDC, &Cd[4], 4*sizeof(*Cd));
		indexDC[1] = indexDC[1] ^ 0x10;
		//printHex("INDEX", index, 4);

		struct dataCollectionEntry *h;

		h = findDataCollectionEntry(indexDC);
		
		if (h) {

			/*-------------------------------------------------------------------------------------------
			 * 2. Identifying the Right Quartets:
			 *-------------------------------------------------------------------------------------------*/

			/*-------------------------------------------------------------------------------------------
			 *	(a) Insert the approximately 2^16 remaining quartets (C_a, C_b, C_c, C_d) into a
					hash table indexed by the 32-bit value C_a^L XOR C_c^L , and apply Step 3 only
					to bins which contain at least three quartets.
			 *-------------------------------------------------------------------------------------------*/

			memcpy(Ca, &(h -> CaCb)[0], 8*sizeof(*Ca));
			memcpy(Cb, &(h -> CaCb)[8], 8*sizeof(*Cb));

			//printHex("Ca", Ca, 8);
			//printHex("Cb", Cb, 8);

			memcpy(indexRQ, &Ca[0], 4*sizeof(*Ca));
			for (int i = 0; i < 4; i++) {
				indexRQ[i] = indexRQ[i] ^ Cb[i];
			}

			addRightQuartetsEntry(indexRQ, Ca, Cb, Cc, Cd);

			//printHex("FOUND", h -> CaCb, 8);
			//printHex("FOUND", h -> CaCb + 8, 8);

			//free(h);		// se lo lascio segfaulta
		}
		//else printf("id unknown\n");

		if (j > z * (nPlaintext/100.0)) {
			printProgress(z/100.0);
			z++;
		} else if (j == nPlaintext - 1) 
			printProgress(1);
	}
	printf("\n");
	/* leaves about 2^16 quartets with the required diﬀerences */
	printf("I have found 2^%.2f potential right quartets.\n", log((double)HASH_COUNT(rightQuartetsTable))/log(2));

	// Free the memory used for the first hash table: the data we need now on are on the new hash table
	deleteAllDataCollectionEntries();

	/*-------------------------------------------------------------------------------------------
	 *		TODO apply Step 3 only to bins which contain at least three quartets.
	 *-------------------------------------------------------------------------------------------*/



	clock_t end = clock();
	double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
	printf("Execution time (s): %.2f\n", time_spent);

	if (!getrusage(RUSAGE_SELF, &usage)) {
		printf("Maximum resident set size (GB): %.2f\n", usage.ru_maxrss/1000000.0);
	} else {
		perror("getrusage");
	}
}


