/*-------------------------------------------------------------------------------------------
 *										Rectangle.c
 *-------------------------------------------------------------------------------------------
 *
 * An implementation of the related-key rectangle attack on the full KASUMI presented by 
 * Bihnam et al.
 *
 *-------------------------------------------------------------------------------------------*/

#include <stdio.h>      // printf()
#include <stdlib.h>		// rand(), srand()
#include <time.h>    	// time()
#include <math.h>       // pow()
#include <sys/resource.h>
#include "uthash.h"     // https://troydhanson.github.io/uthash/
#include "Kasumi.h"


/*---------------------------------------- utility ------------------------------------------*/

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
 * start with a plaintexts quartet (P_a , P_b , P_c , P_d ) such that:
 * P_a xor P_b = P_c xor P_d = A = (0, 0, 0010_x, 0)
 * and use keys (K_a, K_b, K_c, K_d) such that
 * K_a xor K_b = K_c xor K_d = ∆K_ab =  (0, 0, 8000_x, 0, 0, 0, 0, 0)
 * K_a xor K_c = K_b xor K_d = ∆K_ac = (0, 0, 0, 0, 0, 0, 8000_x, 0)
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

/*
struct hashValue {
	u8 Pa[8];           	// value1:  P_a
	u8 Pb[8];				// value2:  P_b
};
*/

struct hashEntry {
	u8 index[8];     	    // key:     (C_a^RL, C_a^RR, C_b^RL, C_b^RR)	 8 Byte
	//struct hashValue PaPb;	
	u8 PaPb[16];			// value:	(P_a, P_b)							16 Byte
	UT_hash_handle hh;  	// makes this structure hashable 				56 Byte
};

struct hashEntry *hashTable = NULL;

void addEntry(u8 index[], u8 Pa[], u8 Pb[]) {dd
	struct hashEntry *h;
	//struct hashValue *v;

	//v = malloc(sizeof(struct hashValue));
	h = malloc(sizeof(struct hashEntry));
	//printf("h size: %ld\n", sizeof(struct hashEntry));	80
	//printf("Pa size: %ld\n", sizeof(UT_hash_handle));		56

	for (int i = 0; i < 8; i++) {
		h -> index[i] = index[i];
		//v -> Pa[i] = Pa[i];
		//v -> Pb[i] = Pb[i];
		h -> PaPb[i] = Pa[i];
		h -> PaPb[i + 8] = Pb[i];
	}

	//h -> PaPb = *v;

	unsigned keylen = (unsigned)sizeof((h)->index);  
	HASH_ADD(hh, hashTable, index[0], keylen, h);
}

struct hashEntry *findEntry(u8 index[]) {
    struct hashEntry *h;

    unsigned keylen = (unsigned)sizeof((h)->index);  
    HASH_FIND(hh, hashTable, index, keylen, h);			// h: output pointer

    return h;
}

void printEntries() {
    struct hashEntry *h;
    //struct hashValue *v;

    for(h = hashTable; h != NULL; h = (struct hashEntry*)(h -> hh.next)) {
    	printHex("H_id", h -> index, 8);

    	//v = &h -> PaPb;
    	//printHex("H_Pa", v -> Pa, 8);
    	//printHex("H_Pb", v -> Pb, 8);
    	printHex("H_Pa", h -> PaPb, 8);
    	printHex("H_Pb", h -> PaPb + 8, 8);
    }
}

/*--------------------------------------- RECTANGLE -----------------------------------------*/

int main(void) {
	clock_t begin = clock();
	time_t t;
	int exp = 24;
	int nPlaintext = pow(2, exp);		// should be pow(2, 38). a pow(2, 26) va in overflow

	printf("Try with 2^%d plaintexts\n", exp);

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
	 *      (a) ask for the encryption of 2^38 plaintexts pairs (P_a, P_b) such that
	 *          P_a xor P_b = A = (0, 0, 0010_x, 0) with keys K_a, K_b
	 *-------------------------------------------------------------------------------------------*/

	srand((unsigned) time(&t));		// Initializes random number generator
	int z = 0;						// Initializes the progress bar

	u8 Pa[8], Pb[8], Pc[8], Pd[8], Ca[8], Cb[8], Cc[8], Cd[8];
	u8 index[8];

	printf("Generating Pa, Pb couples...\n");

	for (int j = 0; j < nPlaintext; j++) {
		
		for (int i = 0; i < 8; i++) {
			Pa[i] = rand() % 255;
			//Pa[i] = 0xff;
		}
		//printHex("Pa", Pa, 8); 

		for (int i = 0; i < 8; i++) {
			if (i == 5)
				Pb[i] = Pa[i] ^ 0x10;
			else
				Pb[i] = Pa[i];
		}
		//printHex("Pb", Pb, 8);

		//for (int i = 0; i < 8; i++) Ca[i] = Pa[i];
		memcpy(Ca, &Pa[0], 8*sizeof(*Pa));
		KeySchedule(Ka);
		Kasumi(Ca);
		//printHex("Ca", Ca, 8);
		//printf("Ca: %p\n", Ca);

		//for (int i = 0; i < 8; i++) Cb[i] = Pb[i];
		memcpy(Cb, &Pb[0], 8*sizeof(*Pb));
		KeySchedule(Kb);
		Kasumi(Cb);
		//printHex("Cb", Cb, 8);

		/*-------------------------------------------------------------------------------------------
		 *          Inserting the plaintext pairs (P_a, P_b)
		 *          into a hash table indexed by the values (C_a^RL, C_a^RR, C_b^RL, C_b^RR)
		 *-------------------------------------------------------------------------------------------*/

		memcpy(index, &Ca[4], 4*sizeof(*Ca));
		memcpy(index+4, &Cb[4], 4*sizeof(*Cb));
		//printHex("INDEX", index, 8);

		addEntry(index, Pa, Pb);
		//printEntries();

		/*
		printf("Searching for element in hash table...\n");

		struct hashEntry *h;
		struct hashValue *v;

		h = findEntry(index);
		v = &h -> PaPb;

		if (h) {
			printHex("INDEX", h -> index, 8);
			printHex("FOUND", v -> Pa, 8);
			printHex("FOUND", v -> Pb, 8);
		}
		else printf("id unknown\n");
		*/

		//printf("%f\n", z * (nPlaintext/100.0));
		//break;
		if (j > z * (nPlaintext/100.0)) {
			printProgress(z/100.0);
			z++;
		} else if (j == nPlaintext - 1) 
			printProgress(1);
	}
	printf("\n");

	printf("Hash table overhead (GB): %.2f\n", HASH_OVERHEAD(hh, hashTable)/1000000000.0);

	/*-------------------------------------------------------------------------------------------
	 *      (b) ask for the encryption for other 2^38 plaintexts pairs (P_c, P_d) such that
	 *          P_c xor P_d = A with keys K_c, K_d
	 *-------------------------------------------------------------------------------------------*/

	z = 1;

	printf("Generating Pc, Pd couples...\n");

	for (int j = 0; j < nPlaintext; j++) {
		for (int i = 0; i < 8; i++) {
			Pc[i] = rand() % 255;
			//Pc[i] = 0x11;
		}
		//printHex("Pc", Pc, 8);

		for (int i = 0; i < 8; i++) {
			if (i == 5)
				Pd[i] = Pc[i] ^ 0x10;
			else
				Pd[i] = Pc[i];
		}
		//printHex("Pd", Pd, 8);
		
		//for (int i = 0; i < 8; i++) Cc[i] = Pc[i];
		memcpy(Cc, &Pc[0], 8*sizeof(*Pc));
		KeySchedule(Kc);
		Kasumi(Cc);
		//printHex("Cc", Cc, 8);

		//for (int i = 0; i < 8; i++) Cd[i] = Pd[i];
		memcpy(Cd, &Pd[0], 8*sizeof(*Pd));
		KeySchedule(Kd);
		Kasumi(Cd);
		//printHex("Cd", Cd, 8);

		/*-------------------------------------------------------------------------------------------
		 *          TODO: for each pair (P_c, P_d) the attacker accesses the hash table in the entry 
		 *          corresponding to the value (C_c^RL xor 0010_x, C_c^RR, C_d^RL xor 0010_x, C_d^RR)
		 *          and for each pair (P_a, P_b) stored in the entry constructs the quartet 
		 *          (P_a, P_b, P_c, P_d).
		 *-------------------------------------------------------------------------------------------*/

		//printf("Searching for element in hash table...\n");

		memcpy(index, &Cc[4], 4*sizeof(*Cc));
		memcpy(index+4, &Cd[4], 4*sizeof(*Cd));
		index[1] = index[1] ^ 0x10;
		index[5] = index[5] ^ 0x10;
		//printHex("INDEX", index, 8);

		struct hashEntry *h;
		//struct hashValue *v;

		h = findEntry(index);
		
		if (h) {
			//v = &h -> PaPb;
			//printHex("FOUND", v -> Pa, 8);
			//printHex("FOUND", v -> Pb, 8);
			printHex("FOUND", h -> PaPb, 8);
			printHex("FOUND", h -> PaPb + 8, 8);

			free(h);
			//free(v);
		}
		//else printf("id unknown\n");
		
		if (j > z * (nPlaintext/100.0)) {
			printProgress(z/100.0);
			z++;
		} else if (j == nPlaintext - 1) 
			printProgress(1);
	}
	printf("\n");

	clock_t end = clock();
	double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
	printf("Execution time (s): %.2f\n", time_spent);

	if (!getrusage(RUSAGE_SELF, &usage)) {
	    printf("Maximum resident set size (GB): %.2f\n", usage.ru_maxrss/1000000.0);
	} else {
	    perror("getrusage");
	}
}