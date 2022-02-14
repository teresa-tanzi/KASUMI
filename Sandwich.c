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
#include "uthash.h"			// https://troydhanson.github.io/uthash/
#include "set.h"			// https://github.com/barrust/set
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

//function to compare array elements
char compareArray(u8 a[], u8 b[], int size)	{
	int i;
	for (i = 0; i < size; i++) {
		if (a[i] != b[i])
			return 0;	// false
	}
	return 1;			// true
}

/*----------------------------------------- KEYS --------------------------------------------*/

static u8 *Ka;
static u8 Kb[16], Kc[16], Kd[16];

/*-------------------------------------------------------------------------------------------
 * Let ΔK_ab = (0, 0, 8000_x, 0, 0, 0, 0, 0) and ΔK_ac = (0, 0, 0, 0, 0, 0, 8000_x , 0), and
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

void deleteRightQuartetsEntry(struct rightQuartetsEntry *h) {
	HASH_DEL(rightQuartetsTable, h);
	free(h);
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

int indexSort(struct rightQuartetsEntry *a, struct rightQuartetsEntry *b) {
	for (int i = 0; i < 4; i++) {
		if ((a -> index)[i] > (b -> index)[i]) {
			return 1;
		} else if ((a -> index)[i] < (b -> index)[i]) {
			return -1;
		}
	}

	return 0;
}

void sortRightQuartetsTable() {
    HASH_SORT(rightQuartetsTable, indexSort);
}

void deleteAllRightQuartetsEntries() {
	struct rightQuartetsEntry *currentEntry, *tmp;

	HASH_ITER(hh, rightQuartetsTable, currentEntry, tmp) {
    	HASH_DEL(rightQuartetsTable, currentEntry);  			/* delete it (entries advances to next) */
    	free(currentEntry);             						/* free it */
    }
}

/*-------------------------------------- KL82 / KL81 ---------------------------------------*/

/*-------------------------------------- FI Function ---------------------------------------*/

static u16 FI(u16 in, u16 subkey) {
	u16 nine, seven;

	static u16 S7[] = {
		54, 50, 62, 56, 22, 34, 94, 96, 38,  6, 63, 93,  2, 18,123, 33,
		55,113, 39,114, 21, 67, 65, 12, 47, 73, 46, 27, 25,111,124, 81,
		53,  9,121, 79, 52, 60, 58, 48,101,127, 40,120,104, 70, 71, 43,
		20,122, 72, 61, 23,109, 13,100, 77,  1, 16,  7, 82, 10,105, 98,
		117,116, 76, 11, 89,106, 0,125,118, 99, 86, 69, 30, 57,126, 87,
		112, 51, 17,  5, 95, 14, 90, 84, 91, 8, 35,103, 32, 97, 28, 66,
		102, 31, 26, 45, 75, 4, 85, 92, 37, 74, 80, 49, 68, 29,115, 44,
		64,107,108, 24,110, 83, 36, 78, 42, 19, 15, 41, 88,119, 59,  3};
	static u16 S9[] = {
		167,239,161,379,391,334,  9,338, 38,226, 48,358,452,385, 90,397,
		183,253,147,331,415,340, 51,362,306,500,262, 82,216,159,356,177,
		175,241,489, 37,206, 17,  0,333, 44,254,378, 58,143,220, 81,400,
		 95,  3,315,245, 54,235,218,405,472,264,172,494,371,290,399, 76,
		165,197,395,121,257,480,423,212,240, 28,462,176,406,507,288,223,
		501,407,249,265, 89,186,221,428,164, 74,440,196,458,421,350,163,
		232,158,134,354, 13,250,491,142,191, 69,193,425,152,227,366,135,
		344,300,276,242,437,320,113,278, 11,243, 87,317, 36, 93,496, 27,
		487,446,482, 41, 68,156,457,131,326,403,339, 20, 39,115,442,124,
		475,384,508, 53,112,170,479,151,126,169, 73,268,279,321,168,364,
		363,292, 46,499,393,327,324, 24,456,267,157,460,488,426,309,229,
		439,506,208,271,349,401,434,236, 16,209,359, 52, 56,120,199,277,
		465,416,252,287,246,  6, 83,305,420,345,153,502, 65, 61,244,282,
		173,222,418, 67,386,368,261,101,476,291,195,430, 49, 79,166,330,
		280,383,373,128,382,408,155,495,367,388,274,107,459,417, 62,454,
		132,225,203,316,234, 14,301, 91,503,286,424,211,347,307,140,374,
		 35,103,125,427, 19,214,453,146,498,314,444,230,256,329,198,285,
		 50,116, 78,410, 10,205,510,171,231, 45,139,467, 29, 86,505, 32,
		 72, 26,342,150,313,490,431,238,411,325,149,473, 40,119,174,355,
		185,233,389, 71,448,273,372, 55,110,178,322, 12,469,392,369,190,
		  1,109,375,137,181, 88, 75,308,260,484, 98,272,370,275,412,111,
		336,318,  4,504,492,259,304, 77,337,435, 21,357,303,332,483, 18,
		 47, 85, 25,497,474,289,100,269,296,478,270,106, 31,104,433, 84,
		414,486,394, 96, 99,154,511,148,413,361,409,255,162,215,302,201,
		266,351,343,144,441,365,108,298,251, 34,182,509,138,210,335,133,
		311,352,328,141,396,346,123,319,450,281,429,228,443,481, 92,404,
		485,422,248,297, 23,213,130,466, 22,217,283, 70,294,360,419,127,
		312,377,  7,468,194,  2,117,295,463,258,224,447,247,187, 80,398,
		284,353,105,390,299,471,470,184, 57,200,348, 63,204,188, 33,451,
		 97, 30,310,219, 94,160,129,493, 64,179,263,102,189,207,114,402,
		438,477,387,122,192, 42,381,  5,145,118,180,449,293,323,136,380,
		 43, 66, 60,455,341,445,202,432,  8,237, 15,376,436,464, 59,461};

	/* The sixteen bit input is split into two unequal halves, 	*
	 * nine bits and seven bits - as is the subkey			   	*/

	nine = (u16)(in>>7);		
	seven = (u16)(in&0x7F);		

	/* Now run the various operations */

	nine = (u16)(S9[nine] ^ seven);				
	seven = (u16)(S7[seven] ^ (nine & 0x7F));

	seven ^= (subkey>>9);		
	nine ^= (subkey&0x1FF);		

	nine = (u16)(S9[nine] ^ seven);
	seven = (u16)(S7[seven] ^ (nine & 0x7F));

	in = (u16)((seven<<9) + nine);

	return(in);
}

u16 rightRotate(u16 n, unsigned int d) {
    return (n >> d) | (n << (16 - d));
}

/*------------------------------------- Lookup Table ---------------------------------------*/

/* 	- 0, 1 	: the guessed bit for KL_8,2 is 0/1 			*
 * 	- 2 	: the guessed bit can be both 0 and 1 			*
 *	- 3 	: there is not a possible guessing for the key 	*/

static short OR[] = 
{
  2, 3, 1, 0,
  3, 3, 3, 3,
  1, 3, 1, 3,
  0, 3, 3, 0
};

/*
static short AND[] = 
{
  2, 3, 0, 1,
  3, 3, 3, 3,
  0, 3, 0, 3,
  1, 3, 3, 1
};
*/

/*------------------------------------- Dynamic Array --------------------------------------*/
// https://stackoverflow.com/questions/3536153/c-dynamically-growing-array

typedef struct {
	int *array;
	size_t used;
	size_t size;
} Array;

void initArray(Array *a, size_t initialSize) {
	a -> array = malloc(initialSize * sizeof(int));
	a -> used = 0;
	a -> size = initialSize;
}

void insertArray(Array *a, int element) {
	// a->used is the number of used entries, because a->array[a->used++] updates a->used only *after* the array has been accessed.
	// Therefore a->used can go up to a->size 
 	if (a -> used == a -> size) {
    	a -> size *= 2;
    	a -> array = realloc(a -> array, a -> size * sizeof(int));
  	}
  	a -> array[a -> used++] = element;
}

void freeArray(Array *a) {
  	free(a -> array);
  	a -> array = NULL;
  	a -> used = a -> size = 0;
}

/*--------------------------------------- Find KL82 ----------------------------------------*/

Array findKL82(u8 *Ca, u8 *Cb, u8 *Cc, u8 *Cd, u16 KO81, u16 KI81) {

    // Finding input and output differences of the OR operator for bot the coupples of texts

    //printf("KO81:\t%04x\n", KO81);
	//printf("KI81:\t%04x\n", KI81);

	//printf("Ca^LL:\t%04x\n", (u16)(Ca[0]<<8)+(Ca[1]));	// Ca^LL
	//printf("Ca^LR:\t%04x\n", (u16)(Ca[2]<<8)+(Ca[3]));	// Ca^LR
	//printf("Ca^RL:\t%04x\n", (u16)(Ca[4]<<8)+(Ca[5]));	// Ca^RL
	//printf("Ca^RR:\t%04x\n", (u16)(Ca[6]<<8)+(Ca[7]));	// Ca^RR

	//printf("Cc^LL:\t%04x\n", (u16)(Cc[0]<<8)+(Cc[1]));	// Cc^LL
	//printf("Cc^LR:\t%04x\n", (u16)(Cc[2]<<8)+(Cc[3]));	// Cc^LR
	//printf("Cc^RL:\t%04x\n", (u16)(Cc[4]<<8)+(Cc[5]));	// Cc^RL
	//printf("Cc^RR:\t%04x\n", (u16)(Cc[6]<<8)+(Cc[7]));	// Cc^RR

	u16 Xac = ((u16)(Ca[2]<<8)+(Ca[3])) ^ ((u16)(Cc[2]<<8)+(Cc[3]));	// Ca^LR ^ Cc^LR
	u16 Xbd = ((u16)(Cb[2]<<8)+(Cb[3])) ^ ((u16)(Cd[2]<<8)+(Cd[3]));	// Cb^LR ^ Cd^LR

	//printf("Xac:\t%04x\n", Xac);
	//printf("Xbd:\t%04x\n", Xbd);

	u16 X1aR = FI(((u16)(Ca[4]<<8)+(Ca[5])) ^ KO81, KI81) ^ ((u16)(Ca[6]<<8)+(Ca[7]));	// FI81( Ca^RL ^ KO81, KI81 ) ^ Ca^RR
	u16 X1cR = FI(((u16)(Cc[4]<<8)+(Cc[5])) ^ KO81, KI81) ^ ((u16)(Cc[6]<<8)+(Cc[7]));	// FI81( Cc^RL ^ KO81, KI81 ) ^ Cc^RR
	u16 X1bR = FI(((u16)(Cb[4]<<8)+(Cb[5])) ^ KO81, KI81) ^ ((u16)(Cb[6]<<8)+(Cb[7]));	// FI81( Cb^RL ^ KO81, KI81 ) ^ Cb^RR
	u16 X1dR = FI(((u16)(Cd[4]<<8)+(Cd[5])) ^ KO81, KI81) ^ ((u16)(Cd[6]<<8)+(Cd[7]));	// FI81( Cd^RL ^ KO81, KI81 ) ^ Cd^RR

	//printf("X1aR:\t%04x\n", X1aR);
	//printf("X1cR:\t%04x\n", X1cR);
	//printf("X1bR:\t%04x\n", X1bR);
	//printf("X1dR:\t%04x\n", X1dR);

	u16 Yac = rightRotate(((u16)(Ca[0]<<8)+(Ca[1])) ^ ((u16)(Cc[0]<<8)+(Cc[1])) ^ X1aR ^ X1cR, 1);	// ( Ca^LL ^ Cc^LL ^ X1a^R ^ X1c^R ) >>> 1
	u16 Ybd = rightRotate(((u16)(Cb[0]<<8)+(Cd[1])) ^ ((u16)(Cb[0]<<8)+(Cd[1])) ^ X1bR ^ X1dR, 1);	// ( Cb^LL ^ Cd^LL ^ X1b^R ^ X1d^R ) >>> 1

	//printf("Yac:\t%04x\n", Yac);
	//printf("Ybd:\t%04x\n", Ybd);

	Array a;					// will contain all the duplicates of the key KL81 in case we found {0,1} in the lookup table
	initArray(&a, 4);	
	int KL82 = 0;
	insertArray(&a, KL82);

	// For each bit in (Xac, Yac, Xbd, Ybd) find the corresponding value of the key KL82 through the lookup table

	for (int p = 0; p < 16; p++) {
		int i = 0;
		int j = 0;

	    if (Xac & 1) i += 2;	// Current bit is set to 1
	    if (Yac & 1) i += 1;
	    if (Xbd & 1) j += 2;
	    if (Ybd & 1) j += 1;

	    int b = OR[4*i + j];

	    if (b == 3) {
	    	freeArray(&a);
	    	break;
	    } else if (b == 1) {
	    	for (int i = 0; i < a.used; i++) {
				a.array[i] = a.array[i] + pow(2, p);
			}
	    } else if (b == 2) {
	    	int nKeys = a.used;
			for (int i = 0; i < nKeys; i++) {
				int m = a.array[i];			// n -> KL82[p] = 0
				m = m + pow(2, p);			// m -> KL82[p] = 1
				insertArray(&a, m);
			}
	    }
				    
		Xac >>= 1;
		Yac >>= 1;
		Xbd >>= 1;
		Ybd >>= 1;
	}

	return a;
}

/*--------------------------------------- SANDWICH -----------------------------------------*/

int main(void) {
	clock_t begin = clock();
	time_t t;
	int exp = 24;
	int nPlaintext = pow(2, exp);       // should be pow(2, 24)

	//int realRightQuartets = 0;
	//int rightQuartets = 0;

	//int nRightQuartets[30];
	//for (int i = 0; i < 30; i++) {
	//	nRightQuartets[i] = 0;
	//}

	//for (int w = 0; w < 1000; w++) {

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

	printf("PHASE 1: DATA COLLECTION\n");
	printf("Generating Ca, Pa, Pb and Cb...\n");

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
		 *      Store the pairs (C_a , C_b) in a hash table indexed by the
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

	printf("Data collection hash table overhead (GB): %.2f\n", HASH_OVERHEAD(hh, dataCollectionTable)/1000000000.0);

	/*-------------------------------------------------------------------------------------------
	 *	(b) Choose a structure of 2^24 ciphertexts of the form C_c = (Y_c , A xor 0010 0000_x),
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
				Cc[4+i] = A[i] ^ 0x10;
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
		 *      corresponding to the value C_d^R xor 00100000_x , and for each pair (C_a, C_b)
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
				indexRQ[i] = indexRQ[i] ^ Cc[i];
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
	printf("I have found 2^%.1f potential right quartets.\n", log((double)HASH_COUNT(rightQuartetsTable))/log(2));

	// Free the memory used for the first hash table: the data we need now on are on the new hash table
	deleteAllDataCollectionEntries();

	/*-------------------------------------------------------------------------------------------
	 *		apply Step 3 only to bins which contain at least three quartets.
	 *-------------------------------------------------------------------------------------------*/

	printf("PHASE 2: IDENTIFIING RIGHT QUARTETS\n");
	printf("Right quartets hash table overhead (GB): %.2f\n", HASH_OVERHEAD(hh, rightQuartetsTable)/1000000000.0);

	sortRightQuartetsTable();

	struct rightQuartetsEntry *q, *tmp;
	u8 currentIndex[4];
	u8 startIndex[4];
	memcpy(currentIndex, rightQuartetsTable -> index, 4*sizeof(*currentIndex));
	memcpy(startIndex, rightQuartetsTable -> index, 4*sizeof(*startIndex));
	int counter = 0;

	HASH_ITER(hh, rightQuartetsTable, q, tmp) {
		if (compareArray(q -> index, currentIndex, 4)) {
			// Found a collision
			counter++;
			/*
			if (counter == 3) {										
				printf("3-collision found!\n");
				printHex("Right quartet index", q -> index, 4);
			}
			*/
		} else 	{
			// Didn't find a collision: delete the elements with no sufficient collisions
			if (counter < 3) {
				while (counter > 0) {				
					deleteRightQuartetsEntry(findRightQuartetsEntry(currentIndex));
					counter--;
				}
			}
			counter = 1;
			memcpy(currentIndex, q -> index, 4 * sizeof(*currentIndex));
		}
	}

	// Delete the last quartet if not in a 3-collision
	if (counter < 3) {
		deleteRightQuartetsEntry(findRightQuartetsEntry(currentIndex));
	}

	//printRightQuartetsEntries();
	printf("I have found %d right quartets.\n", HASH_COUNT(rightQuartetsTable));

	//nRightQuartets[HASH_COUNT(rightQuartetsTable)]++;
	//rightQuartets += HASH_COUNT(rightQuartetsTable);
	
	//u8 rightIndex[] = {0x83, 0xf2, 0x98, 0xfc};

	//HASH_ITER(hh, rightQuartetsTable, q, tmp) {
	//	if (!compareArray(q -> index, rightIndex, 4)) {
	//		deleteRightQuartetsEntry(q);
	//	}
	//}

	//realRightQuartets += HASH_COUNT(rightQuartetsTable);

	// Free the memory used for the first hash table: the data we need now on are on the new hash table
	//deleteAllRightQuartetsEntries();
	//}

	//for (int i = 0; i < 30; i++) {
	//	printf("Number of right quartets: \t%d. \tFound: \t%d\n", i, nRightQuartets[i]);
	//}

	//printf("Right quartets found: \t%d, of which are real: \t%d\n", rightQuartets, realRightQuartets);

	/*-------------------------------------------------------------------------------------------
	 * 3. Analyzing Right Quartets: (TODO)
	 *-------------------------------------------------------------------------------------------*/

	if (HASH_COUNT(rightQuartetsTable) == 0) {
		printf("No right quartet found, can't proceed with the attack.\n");
		exit(0);
	}

	/*
	u8 rightIndex[] = {0x83, 0xf2, 0x98, 0xfc};
	u8 diffAC[8], diffBD[8];
	//u8 diffAB[8], diffCD[8];
	//u8 Ca[8], Cb[8], Cc[8], Cd[8];

	HASH_ITER(hh, rightQuartetsTable, q, tmp) {
		if (compareArray(q -> index, rightIndex, 4)) {
			for (int i = 1; i < 8; i++) {
				Ca[i] = (q -> CaCbCcCd)[i];
				Cb[i] = (q -> CaCbCcCd)[i + 8];
				Cc[i] = (q -> CaCbCcCd)[i + 16];
				Cd[i] = (q -> CaCbCcCd)[i + 24];
			}

			for (int i = 1; i < 8; i++) {
				diffAC[i] = Ca[i] ^ Cc[i];
				diffBD[i] = Cb[i] ^ Cd[i];
				//diffAB[i] = Ca[i] ^ Cb[i];
				//diffCD[i] = Cc[i] ^ Cd[i];
			}

			printHex("Ca XOR Cc", diffAC, 8);				
			printHex("Cb XOR Cd", diffBD, 8);	
			//printHex("Ca XOR Cb", diffAB, 8);				
			//printHex("Cc XOR Cd", diffCD, 8);	
		}
	}
	*/

	/*-------------------------------------------------------------------------------------------
	 *	(a) For each remaining quartet (C_a, C_b, C_c, C_d), guess the 32-bit value of
	 *		KO_8,1 and KI_8,1 
	 *-------------------------------------------------------------------------------------------*/

	printf("PHASE 3: ANALYZING RIGHT QUARTETS\n");

	int cont = 1;

	u16 KO81 = 0x0000;
	u16 KI81 = 0x0000;

	for (q = rightQuartetsTable; q != NULL; q = q->hh.next) {
		printf("Analysing quartet n. %d...\n", cont);

		for (int i = 1; i < 8; i++) {
			Ca[i] = (q -> CaCbCcCd)[i];
			Cb[i] = (q -> CaCbCcCd)[i + 8];
			Cc[i] = (q -> CaCbCcCd)[i + 16];
			Cd[i] = (q -> CaCbCcCd)[i + 24];
		}

		printHex("Ca", Ca, 8);				
		printHex("Cb", Cb, 8);
		printHex("Cc", Cc, 8);				
		printHex("Cd", Cd, 8);

		/*-------------------------------------------------------------------------------------------
		 *		For the two pairs (C_a, C_c) and (C_b, C_d) use the value of the guessed key 
		 *		to compute the input and output diﬀerences of the OR operation in the last 
		 *		round of both pairs. For each bit of this 16-bit OR operation of F L8, 
		 *		the possible values of the corresponding bit of KL 8,2 are given
		 *-------------------------------------------------------------------------------------------*/

		printf("Guessing the keys KO81 and KO82...\n");

		z = 0;	// Initializing the progress bar

		for (int ko = 0; ko <= 0x0fff; ko++) {
			for (int ki = 0; ki <= 0x0fff; ki++) {

				//SimpleSet set;
    			//set_init(&set);

    			Array a = findKL82(Ca, Cb, Cc, Cd, KO81, KI81);

    			if (a.used > 0) {
    				printf("\n");
    				printf("KO81:\t%04x\n", KO81);
    				printf("KI81:\t%04x\n", KI81);

    				for (int i = 0; i < a.used; i++) {
						printf("KL82 %d:\t%04x\n", i, a.array[i]);
					}

					// TODO: inserire (KO81, KI81, KL82) nell'insieme di possibili chiavi
    			}

    			freeArray(&a);

				//if (KI81 < 0xffff) KI81++;
				KI81++;

				if ((u32)((KO81<<16)+(KI81)) > z * (pow(2,32)/100.0)) {
					printProgress(z/100.0);
					z++;
				} else if ((u32)((KO81<<16)+(KI81)) == pow(2,32) - 1) {
					printProgress(1);
				}

				//printf("%08x\n", (u32)((KO81<<16)+(KI81)));

			}

			//if (KO81 < 0xffff) {
			KO81++;
			KI81 = 0x0000;
			//}
		}
		printf("\n");
		/*
		printf("%x\n", (u32)((KO81<<16)+(KI81)));
		printf("%x\n", (int)pow(2,32));
		printf("%f\n", pow(2,32));
		*/

		cont++;
		break;
	}

	

	/*-------------------------------------------------------------------------------------------
	 *		Since all the right quartets suggest the same key, all the wrong keys are discarded
	 * 		and the attacker obtains the correct value of (KO_8,1, KI_8,1, KL_8,2)
	 *-------------------------------------------------------------------------------------------*/

	/*-------------------------------------------------------------------------------------------
	 *	(b) Guess the 32-bit value of KO_8,3 and KI_8,3
	 *-------------------------------------------------------------------------------------------*/

	/*-------------------------------------------------------------------------------------------
	 *		compute the input and output diﬀerences of the AND operation in both pairs
	 		of each quartet. For each bit of the 16-bit AND operation of F L8, 
	 		the possible values of the corresponding bit of KL_8,1 are given
	 *-------------------------------------------------------------------------------------------*/

	/*-------------------------------------------------------------------------------------------
	 *		the attacker obtains the correct value of (KO_8,3, KI_8,3, KL_8,1)
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
