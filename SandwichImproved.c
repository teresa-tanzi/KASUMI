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
//#include "set.h"			// https://github.com/barrust/set
//#include "set.c"
//#include "pblSet.c"	
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
//static u8 Ka[16];
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

void printDataCollectionEntries(void) {
	struct dataCollectionEntry *h;

	for(h = dataCollectionTable; h != NULL; h = (struct dataCollectionEntry*)(h -> hh.next)) {
		printHex("Id", h -> index, 4);
		printHex("Ca", h -> CaCb, 8);
		printHex("Cb", h -> CaCb + 8, 8);
	}
}

void deleteAllDataCollectionEntries(void) {
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

void printRightQuartetsEntries(void) {
	struct rightQuartetsEntry *h;

	for(h = rightQuartetsTable; h != NULL; h = (struct rightQuartetsEntry*)(h -> hh.next)) {
		printHex("Id", h -> index, 4);
		printHex("Ca", h -> CaCbCcCd, 8);
		printHex("Cb", h -> CaCbCcCd + 8, 8);
		printHex("Cc", h -> CaCbCcCd + 16, 8);
		printHex("Cd", h -> CaCbCcCd + 24, 8);
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

void sortRightQuartetsTable(void) {
	HASH_SORT(rightQuartetsTable, indexSort);
}

void deleteAllRightQuartetsEntries(void) {
	struct rightQuartetsEntry *currentEntry, *tmp;

	HASH_ITER(hh, rightQuartetsTable, currentEntry, tmp) {
		HASH_DEL(rightQuartetsTable, currentEntry);  			/* delete it (entries advances to next) */
		free(currentEntry);             						/* free it */
	}
}

/*--------------------------------------- OR^R Set ------------------------------------------*/

struct OrREntry {
	u16 index[3];       	// key:		(KO81, KI81, KL82)     				48 Byte  
	UT_hash_handle hh;      // makes this structure hashable                56 Byte
};

struct OrREntry *OrRSet = NULL;

struct OrREntry *findOrREntry(u16 KO81, u16 KI81, u16 KL82) {
	struct OrREntry *h;
	u16 index[3] = {KO81, KI81, KL82};

	unsigned keylen = (unsigned)sizeof((h)->index);  
	HASH_FIND(hh, OrRSet, index, keylen, h);         // h: output pointer

	return h;
}

void addOrREntry(u16 KO81, u16 KI81, u16 KL82) {
	struct OrREntry *h;

	// As a set, we should avoid repetition of the key
	if (!findOrREntry(KO81, KI81, KL82)) {
		h = malloc(sizeof(struct OrREntry));

		h -> index[0] = KO81;
		h -> index[1] = KI81;
		h -> index[2] = KL82;

		unsigned keylen = (unsigned)sizeof((h)->index);  
		HASH_ADD(hh, OrRSet, index[0], keylen, h);
	}
}

void printOrREntries(void) {
	struct OrREntry *h;

	for(h = OrRSet; h != NULL; h = (struct OrREntry*)(h -> hh.next)) {
		printf("(KO81, KI81^R, KL82^R):\t(%04x, %04x, %04x)\n", h -> index[0], h -> index[1], h -> index[2]);
	}
}

void deleteAllOrREntries(void) {
	struct OrREntry *currentEntry, *tmp;

	HASH_ITER(hh, OrRSet, currentEntry, tmp) {
		HASH_DEL(OrRSet, currentEntry);  			/* delete it (entries advances to next) */
		free(currentEntry);             						/* free it */
	}
}

/*------------------------------------- tmp OR^R Set ----------------------------------------*/

struct tmpOrREntry {
	u16 index[3];       	// key:		(KO81, KI81, KL82)     				48 Byte  
	UT_hash_handle hh;      // makes this structure hashable                56 Byte
};

struct tmpOrREntry *tmpOrRSet = NULL;

struct tmpOrREntry *findTmpOrREntry(u16 KO81, u16 KI81, u16 KL82) {
	struct tmpOrREntry *h;
	u16 index[3] = {KO81, KI81, KL82};

	unsigned keylen = (unsigned)sizeof((h)->index);  
	HASH_FIND(hh, tmpOrRSet, index, keylen, h);

	return h;
}

void addTmpOrREntry(u16 KO81, u16 KI81, u16 KL82) {
	struct tmpOrREntry *h;

	if (!findTmpOrREntry(KO81, KI81, KL82)) {
		h = malloc(sizeof(struct OrREntry));

		h -> index[0] = KO81;
		h -> index[1] = KI81;
		h -> index[2] = KL82;

		unsigned keylen = (unsigned)sizeof((h)->index);  
		HASH_ADD(hh, tmpOrRSet, index[0], keylen, h);
	}
}

void printTmpOrREntries(void) {
	struct tmpOrREntry *h;

	for(h = tmpOrRSet; h != NULL; h = (struct tmpOrREntry*)(h -> hh.next)) {
		printf("(KO81, KI81, KL82):\t(%04x, %04x, %04x)\n", h -> index[0], h -> index[1], h -> index[2]);
	}
}

void deleteAllTmpOrREntries(void) {
	struct tmpOrREntry *currentEntry, *tmp;

	HASH_ITER(hh, tmpOrRSet, currentEntry, tmp) {
		HASH_DEL(tmpOrRSet, currentEntry);  			/* delete it (entries advances to next) */
		free(currentEntry);             						/* free it */
	}
}

/*---------------------------------------- OR Set -------------------------------------------*/

struct OrEntry {
	u16 index[3];       	// key:		(KO81, KI81, KL82)     				48 Byte  
	UT_hash_handle hh;      // makes this structure hashable                56 Byte
};

struct OrEntry *OrSet = NULL;

struct OrEntry *findOrEntry(u16 KO81, u16 KI81, u16 KL82) {
	struct OrEntry *h;
	u16 index[3] = {KO81, KI81, KL82};

	unsigned keylen = (unsigned)sizeof((h)->index);  
	HASH_FIND(hh, OrSet, index, keylen, h);         // h: output pointer

	return h;
}

void addOrEntry(u16 KO81, u16 KI81, u16 KL82) {
	struct OrEntry *h;

	// As a set, we should avoid repetition of the key
	if (!findOrEntry(KO81, KI81, KL82)) {
		h = malloc(sizeof(struct OrEntry));

		h -> index[0] = KO81;
		h -> index[1] = KI81;
		h -> index[2] = KL82;

		unsigned keylen = (unsigned)sizeof((h)->index);  
		HASH_ADD(hh, OrSet, index[0], keylen, h);
	}
}

void printOrEntries(void) {
	struct OrEntry *h;

	for(h = OrSet; h != NULL; h = (struct OrEntry*)(h -> hh.next)) {
		printf("(KO81, KI81, KL82):\t(%04x, %04x, %04x)\n", h -> index[0], h -> index[1], h -> index[2]);
	}
}

void deleteAllOrEntries(void) {
	struct OrEntry *currentEntry, *tmp;

	HASH_ITER(hh, OrSet, currentEntry, tmp) {
		HASH_DEL(OrSet, currentEntry);  			/* delete it (entries advances to next) */
		free(currentEntry);             						/* free it */
	}
}

/*-------------------------------------- tmp OR Set -----------------------------------------*/

struct tmpOrEntry {
	u16 index[3];       	// key:		(KO81, KI81, KL82)     				48 Byte  
	UT_hash_handle hh;      // makes this structure hashable                56 Byte
};

struct tmpOrEntry *tmpOrSet = NULL;

struct tmpOrEntry *findTmpOrEntry(u16 KO81, u16 KI81, u16 KL82) {
	struct tmpOrEntry *h;
	u16 index[3] = {KO81, KI81, KL82};

	unsigned keylen = (unsigned)sizeof((h)->index);  
	HASH_FIND(hh, tmpOrSet, index, keylen, h);

	return h;
}

void addTmpOrEntry(u16 KO81, u16 KI81, u16 KL82) {
	struct tmpOrEntry *h;

	if (!findTmpOrEntry(KO81, KI81, KL82)) {
		h = malloc(sizeof(struct OrEntry));

		h -> index[0] = KO81;
		h -> index[1] = KI81;
		h -> index[2] = KL82;

		unsigned keylen = (unsigned)sizeof((h)->index);  
		HASH_ADD(hh, tmpOrSet, index[0], keylen, h);
	}
}

void printTmpOrEntries(void) {
	struct tmpOrEntry *h;

	for(h = tmpOrSet; h != NULL; h = (struct tmpOrEntry*)(h -> hh.next)) {
		printf("(KO81, KI81, KL82):\t(%04x, %04x, %04x)\n", h -> index[0], h -> index[1], h -> index[2]);
	}
}

void deleteAllTmpOrEntries(void) {
	struct tmpOrEntry *currentEntry, *tmp;

	HASH_ITER(hh, tmpOrSet, currentEntry, tmp) {
		HASH_DEL(tmpOrSet, currentEntry);  			/* delete it (entries advances to next) */
		free(currentEntry);             						/* free it */
	}
}

/*-------------------------------------- AND^R Set ------------------------------------------*/

struct AndREntry {
	u16 index[3];       	// key:		(KO83, KI83, KL81)     				48 Byte  
	UT_hash_handle hh;      // makes this structure hashable                56 Byte
};

struct AndREntry *AndRSet = NULL;

struct AndREntry *findAndREntry(u16 KO83, u16 KI83, u16 KL81) {
	struct AndREntry *h;
	u16 index[3] = {KO83, KI83, KL81};

	unsigned keylen = (unsigned)sizeof((h)->index);  
	HASH_FIND(hh, AndRSet, index, keylen, h);         

	return h;
}

void addAndREntry(u16 KO83, u16 KI83, u16 KL81) {
	struct AndREntry *h;

	if (!findAndREntry(KO83, KI83, KL81)) {
		h = malloc(sizeof(struct AndREntry));

		h -> index[0] = KO83;
		h -> index[1] = KI83;
		h -> index[2] = KL81;

		unsigned keylen = (unsigned)sizeof((h)->index);  
		HASH_ADD(hh, AndRSet, index[0], keylen, h);
	}
}

void printAndREntries(void) {
	struct AndREntry *h;

	for(h = AndRSet; h != NULL; h = (struct AndREntry*)(h -> hh.next)) {
		printf("(KO83, KI83, KL81):\t(%04x, %04x, %04x)\n", h -> index[0], h -> index[1], h -> index[2]);
	}
}

void deleteAllAndREntries(void) {
	struct AndREntry *currentEntry, *tmp;

	HASH_ITER(hh, AndRSet, currentEntry, tmp) {
		HASH_DEL(AndRSet, currentEntry);  			/* delete it (entries advances to next) */
		free(currentEntry);             						/* free it */
	}
}

/*------------------------------------ tmp AND^R Set ----------------------------------------*/

struct tmpAndREntry {
	u16 index[3];       	// key:		(KO83, KI83, KL81)					48 Byte  
	UT_hash_handle hh;      // makes this structure hashable                56 Byte
};

struct tmpAndREntry *tmpAndRSet = NULL;

struct tmpAndREntry *findTmpAndREntry(u16 KO83, u16 KI83, u16 KL81) {
	struct tmpAndREntry *h;
	u16 index[3] = {KO83, KI83, KL81};

	unsigned keylen = (unsigned)sizeof((h)->index);  
	HASH_FIND(hh, tmpAndRSet, index, keylen, h);         

	return h;
}

void addTmpAndREntry(u16 KO83, u16 KI83, u16 KL81) {
	struct tmpAndREntry *h;

	if (!findTmpAndREntry(KO83, KI83, KL81)) {
		h = malloc(sizeof(struct AndREntry));

		h -> index[0] = KO83;
		h -> index[1] = KI83;
		h -> index[2] = KL81;

		unsigned keylen = (unsigned)sizeof((h)->index);  
		HASH_ADD(hh, tmpAndRSet, index[0], keylen, h);
	}
}

void printTmpAndREntries(void) {
	struct tmpAndREntry *h;

	for(h = tmpAndRSet; h != NULL; h = (struct tmpAndREntry*)(h -> hh.next)) {
		printf("(KO83, KI83, KL81):\t(%04x, %04x, %04x)\n", h -> index[0], h -> index[1], h -> index[2]);
	}
}

void deleteAllTmpAndREntries(void) {
	struct tmpAndREntry *currentEntry, *tmp;

	HASH_ITER(hh, tmpAndRSet, currentEntry, tmp) {
		HASH_DEL(tmpAndRSet, currentEntry);  			/* delete it (entries advances to next) */
		free(currentEntry);             						/* free it */
	}
}

/*--------------------------------------- AND Set -------------------------------------------*/

struct AndEntry {
	u16 index[3];       	// key:		(KO83, KI83, KL81)     				48 Byte  
	UT_hash_handle hh;      // makes this structure hashable                56 Byte
};

struct AndEntry *AndSet = NULL;

struct AndEntry *findAndEntry(u16 KO83, u16 KI83, u16 KL81) {
	struct AndEntry *h;
	u16 index[3] = {KO83, KI83, KL81};

	unsigned keylen = (unsigned)sizeof((h)->index);  
	HASH_FIND(hh, AndSet, index, keylen, h);         

	return h;
}

void addAndEntry(u16 KO83, u16 KI83, u16 KL81) {
	struct AndEntry *h;

	if (!findAndEntry(KO83, KI83, KL81)) {
		h = malloc(sizeof(struct AndEntry));

		h -> index[0] = KO83;
		h -> index[1] = KI83;
		h -> index[2] = KL81;

		unsigned keylen = (unsigned)sizeof((h)->index);  
		HASH_ADD(hh, AndSet, index[0], keylen, h);
	}
}

void printAndEntries(void) {
	struct AndEntry *h;

	for(h = AndSet; h != NULL; h = (struct AndEntry*)(h -> hh.next)) {
		printf("(KO83, KI83, KL81):\t(%04x, %04x, %04x)\n", h -> index[0], h -> index[1], h -> index[2]);
	}
}

void deleteAllAndEntries(void) {
	struct AndEntry *currentEntry, *tmp;

	HASH_ITER(hh, AndSet, currentEntry, tmp) {
		HASH_DEL(AndSet, currentEntry);  			/* delete it (entries advances to next) */
		free(currentEntry);             						/* free it */
	}
}

/*------------------------------------- tmp AND Set -----------------------------------------*/

struct tmpAndEntry {
	u16 index[3];       	// key:		(KO83, KI83, KL81)					48 Byte  
	UT_hash_handle hh;      // makes this structure hashable                56 Byte
};

struct tmpAndEntry *tmpAndSet = NULL;

struct tmpAndEntry *findTmpAndEntry(u16 KO83, u16 KI83, u16 KL81) {
	struct tmpAndEntry *h;
	u16 index[3] = {KO83, KI83, KL81};

	unsigned keylen = (unsigned)sizeof((h)->index);  
	HASH_FIND(hh, tmpAndSet, index, keylen, h);         

	return h;
}

void addTmpAndEntry(u16 KO83, u16 KI83, u16 KL81) {
	struct tmpAndEntry *h;

	if (!findTmpAndEntry(KO83, KI83, KL81)) {
		h = malloc(sizeof(struct AndEntry));

		h -> index[0] = KO83;
		h -> index[1] = KI83;
		h -> index[2] = KL81;

		unsigned keylen = (unsigned)sizeof((h)->index);  
		HASH_ADD(hh, tmpAndSet, index[0], keylen, h);
	}
}

void printTmpAndEntries(void) {
	struct tmpAndEntry *h;

	for(h = tmpAndSet; h != NULL; h = (struct tmpAndEntry*)(h -> hh.next)) {
		printf("(KO83, KI83, KL81):\t(%04x, %04x, %04x)\n", h -> index[0], h -> index[1], h -> index[2]);
	}
}

void deleteAllTmpAndEntries(void) {
	struct tmpAndEntry *currentEntry, *tmp;

	HASH_ITER(hh, tmpAndSet, currentEntry, tmp) {
		HASH_DEL(tmpAndSet, currentEntry);  			/* delete it (entries advances to next) */
		free(currentEntry);             						/* free it */
	}
}

/*-------------------------------------- Subkeys Set ----------------------------------------*/

struct SubkeysEntry {
	u16 index[6];       	// key:		(KO81, KI81, KL82, KO83, KI83, KL81)    96 Byte  
	UT_hash_handle hh;      // makes this structure hashable                	56 Byte
};

struct SubkeysEntry *SubkeysSet = NULL;

struct SubkeysEntry *findSubkeysEntry(u16 KO81, u16 KI81, u16 KL82, u16 KO83, u16 KI83, u16 KL81) {
	struct SubkeysEntry *h;
	u16 index[6] = {KO81, KI81, KL82, KO83, KI83, KL81};

	unsigned keylen = (unsigned)sizeof((h)->index);  
	HASH_FIND(hh, SubkeysSet, index, keylen, h);

	return h;
}

void addSubkeysEntry(u16 KO81, u16 KI81, u16 KL82, u16 KO83, u16 KI83, u16 KL81) {
	struct SubkeysEntry *h;

	if (!findSubkeysEntry(KO81, KI81, KL82, KO83, KI83, KL81)) {
		h = malloc(sizeof(struct SubkeysEntry));

		h -> index[0] = KO81;
		h -> index[1] = KI81;
		h -> index[2] = KL82;
		h -> index[3] = KO83;
		h -> index[4] = KI83;
		h -> index[5] = KL81;

		unsigned keylen = (unsigned)sizeof((h)->index);  
		HASH_ADD(hh, SubkeysSet, index[0], keylen, h);
	}
}

void printSubkeysEntries(void) {
	struct SubkeysEntry *h;

	for(h = SubkeysSet; h != NULL; h = (struct SubkeysEntry*)(h -> hh.next)) {
		printf("(KO81, KI81, KL82, KO83, KI83, KL81):\t(%04x, %04x, %04x, %04x, %04x, %04x)\n", 
			h -> index[0], h -> index[1], h -> index[2], h -> index[3], h -> index[4], h -> index[5]);
	}
}

void deleteAllSubkeysEntries(void) {
	struct SubkeysEntry *currentEntry, *tmp;

	HASH_ITER(hh, SubkeysSet, currentEntry, tmp) {
		HASH_DEL(SubkeysSet, currentEntry);  			/* delete it (entries advances to next) */
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

static short AND[] = 
{
  2, 3, 0, 1,
  3, 3, 3, 3,
  0, 3, 0, 3,
  1, 3, 3, 1
};

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

Array findKL82R(u8 *Ca, u8 *Cb, u8 *Cc, u8 *Cd, u16 KO81, u16 KI81) {

	// Finding input and output differences of the OR operator for bot the coupples of texts
	// Ca^LL = (u16)(Ca[0]<<8)+(Ca[1])
	// Ca^LR = (u16)(Ca[2]<<8)+(Ca[3])
	// Ca^RL = (u16)(Ca[4]<<8)+(Ca[5])
	// Ca^RR = (u16)(Ca[6]<<8)+(Ca[7])

	u16 Xac = ((u16)(Ca[2]<<8)+(Ca[3])) ^ ((u16)(Cc[2]<<8)+(Cc[3]));	// Ca^LR ^ Cc^LR
	u16 Xbd = ((u16)(Cb[2]<<8)+(Cb[3])) ^ ((u16)(Cd[2]<<8)+(Cd[3]));	// Cb^LR ^ Cd^LR
	u16 Ya = FI(((u16)(Ca[4]<<8)+(Ca[5])) ^ KO81, KI81);
	u16 Yb = FI(((u16)(Cb[4]<<8)+(Cb[5])) ^ KO81, KI81);
	u16 Yc = FI(((u16)(Cc[4]<<8)+(Cc[5])) ^ KO81, KI81);
	u16 Yd = FI(((u16)(Cd[4]<<8)+(Cd[5])) ^ KO81, KI81);

	u16 Yac = rightRotate(Ya ^ Yc ^ (u16)((Ca[0]<<8)+(Ca[1])) ^ (u16)((Cc[0]<<8)+(Cc[1])), 1);
	u16 Ybd = rightRotate(Yb ^ Yd ^ (u16)((Cb[0]<<8)+(Cb[1])) ^ (u16)((Cd[0]<<8)+(Cd[1])), 1);

	Array a;					// will contain all the duplicates of the key KL82 in case we found {0,1} in the lookup table
	initArray(&a, 4);	
	int KL82 = 0;
	insertArray(&a, KL82);

	// For each bit in (Xac, Yac, Xbd, Ybd) find the corresponding value of the key KL82 through the lookup table

	for (int p = 0; p < 16; p++) {
		int b;

		if (p > 7 && p < 15) {
			b = 0;
		} else {
			int i = 0;
			int j = 0;

			if (Xac & 1) i += 2;	// Current bit is set to 1
			if (Yac & 1) i += 1;
			if (Xbd & 1) j += 2;
			if (Ybd & 1) j += 1;

			b = OR[4*i + j];
		}

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
	
	return a;	// vettore in cui per tutti i numeri i primi 7 bit sono a 0: ancora non li abbiamo checkati
}

Array findKL82L(u8 *Ca, u8 *Cb, u8 *Cc, u8 *Cd, u16 KO81, u16 KI81, u16 KL82R) {

	// Finding input and output differences of the OR operator for bot the coupples of texts
	// Ca^LL = (u16)(Ca[0]<<8)+(Ca[1])
	// Ca^LR = (u16)(Ca[2]<<8)+(Ca[3])
	// Ca^RL = (u16)(Ca[4]<<8)+(Ca[5])
	// Ca^RR = (u16)(Ca[6]<<8)+(Ca[7])

	u16 Xac = ((u16)(Ca[2]<<8)+(Ca[3])) ^ ((u16)(Cc[2]<<8)+(Cc[3]));	// Ca^LR ^ Cc^LR
	u16 Xbd = ((u16)(Cb[2]<<8)+(Cb[3])) ^ ((u16)(Cd[2]<<8)+(Cd[3]));	// Cb^LR ^ Cd^LR
	u16 Ya = FI(((u16)(Ca[4]<<8)+(Ca[5])) ^ KO81, KI81);
	u16 Yb = FI(((u16)(Cb[4]<<8)+(Cb[5])) ^ KO81, KI81);
	u16 Yc = FI(((u16)(Cc[4]<<8)+(Cc[5])) ^ KO81, KI81);
	u16 Yd = FI(((u16)(Cd[4]<<8)+(Cd[5])) ^ KO81, KI81);

	u16 Yac = rightRotate(Ya ^ Yc ^ (u16)((Ca[0]<<8)+(Ca[1])) ^ (u16)((Cc[0]<<8)+(Cc[1])), 1);
	u16 Ybd = rightRotate(Yb ^ Yd ^ (u16)((Cb[0]<<8)+(Cb[1])) ^ (u16)((Cd[0]<<8)+(Cd[1])), 1);

	Array a;					// will contain all the duplicates of the key KL82 in case we found {0,1} in the lookup table
	initArray(&a, 4);	
	int KL82 = KL82R;
	insertArray(&a, KL82);

	// For each bit in (Xac, Yac, Xbd, Ybd) find the corresponding value of the key KL82 through the lookup table

	for (int p = 0; p < 16; p++) {
		int b = 0;

		if (p > 7 && p < 15) {
			int i = 0;
			int j = 0;

			if (Xac & 1) i += 2;	// Current bit is set to 1
			if (Yac & 1) i += 1;
			if (Xbd & 1) j += 2;
			if (Ybd & 1) j += 1;

			b = OR[4*i + j];
		}

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
	
	return a;	// vettore in cui per tutti i numeri i primi 7 bit sono a 0: ancora non li abbiamo checkati
}

/*--------------------------------------- Find KL81 ----------------------------------------*/

Array findKL81R(u8 *Ca, u8 *Cb, u8 *Cc, u8 *Cd, u16 KO81, u16 KI81, u16 KO83, u16 KI83) {

	// Finding input and output differences of the OR operator for bot the coupples of texts
	// Ca^LL = (u16)(Ca[0]<<8)+(Ca[1])
	// Ca^LR = (u16)(Ca[2]<<8)+(Ca[3])
	// Ca^RL = (u16)(Ca[4]<<8)+(Ca[5])
	// Ca^RR = (u16)(Ca[6]<<8)+(Ca[7])

	u16 X1a = FI(((u16)(Ca[4]<<8)+(Ca[5])) ^ KO81, KI81);		// FI(CaRL ^ KO81, KI81)
	u16 X1b = FI(((u16)(Cb[4]<<8)+(Cb[5])) ^ KO81, KI81);		
	u16 X1c = FI(((u16)(Cc[4]<<8)+(Cc[5])) ^ KO81, KI81);		
	u16 X1d = FI(((u16)(Cd[4]<<8)+(Cd[5])) ^ KO81, KI81);		

	u16 Xa = FI(X1a ^ ((u16)(Ca[6]<<8)+(Ca[7])) ^ KO83, KI83) ^ X1a;				// FI(X1a ^ CaRR ^ KO83, KI83) ^ X1a	
	u16 Xb = FI(X1b ^ ((u16)(Cb[6]<<8)+(Cb[7])) ^ KO83, KI83) ^ X1b;	
	u16 Xc = FI(X1c ^ ((u16)(Cc[6]<<8)+(Cc[7])) ^ KO83, KI83 ^ 0x8000) ^ X1c;	
	u16 Xd = FI(X1d ^ ((u16)(Cd[6]<<8)+(Cd[7])) ^ KO83, KI83 ^ 0x8000) ^ X1d;	

	u16 Yac = rightRotate(Xa ^ Xc ^ ((u16)(Ca[2]<<8)+(Ca[3])) ^ ((u16)(Cc[2]<<8)+(Cc[3])), 1);	//(Xa ^ Xc ^ CaLR ^ CcLR) >>> 1
	u16 Ybd = rightRotate(Xb ^ Xd ^ ((u16)(Cb[2]<<8)+(Cb[3])) ^ ((u16)(Cd[2]<<8)+(Cd[3])), 1);

	u16 Xac = X1a ^ X1c;
	u16 Xbd = X1b ^ X1d;

	Array a;					// will contain all the duplicates of the key KL81 in case we found {0,1} in the lookup table
	initArray(&a, 4);	
	int KL81 = 0;
	insertArray(&a, KL81);

	// For each bit in (Xac, Yac, Xbd, Ybd) find the corresponding value of the key KL82 through the lookup table

	for (int p = 0; p < 16; p++) {
		int b;

		if (p > 7 && p < 15) {
			b = 0;
		} else {
			int i = 0;
			int j = 0;

			if (Xac & 1) i += 2;	// Current bit is set to 1
			if (Yac & 1) i += 1;
			if (Xbd & 1) j += 2;
			if (Ybd & 1) j += 1;

			//printf("p: %d\t", 4*i + j);

			b = AND[4*i + j];
		}

		//printf("b: %d\n", b);

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
				int m = a.array[i];			// n -> KL81[p] = 0
				m = m + pow(2, p);			// m -> KL81[p] = 1
				insertArray(&a, m);
			}
		}
					
		Xac >>= 1;
		Yac >>= 1;
		Xbd >>= 1;
		Ybd >>= 1;
	}

	//printf("\n");

	return a;
}


Array findKL81L(u8 *Ca, u8 *Cb, u8 *Cc, u8 *Cd, u16 KO81, u16 KI81, u16 KO83, u16 KI83, u16 KL81R) {

	// Finding input and output differences of the OR operator for bot the coupples of texts
	// Ca^LL = (u16)(Ca[0]<<8)+(Ca[1])
	// Ca^LR = (u16)(Ca[2]<<8)+(Ca[3])
	// Ca^RL = (u16)(Ca[4]<<8)+(Ca[5])
	// Ca^RR = (u16)(Ca[6]<<8)+(Ca[7])

	u16 X1a = FI(((u16)(Ca[4]<<8)+(Ca[5])) ^ KO81, KI81);		// FI(CaRL ^ KO81, KI81)
	u16 X1b = FI(((u16)(Cb[4]<<8)+(Cb[5])) ^ KO81, KI81);		
	u16 X1c = FI(((u16)(Cc[4]<<8)+(Cc[5])) ^ KO81, KI81);		
	u16 X1d = FI(((u16)(Cd[4]<<8)+(Cd[5])) ^ KO81, KI81);		

	u16 Xa = FI(X1a ^ ((u16)(Ca[6]<<8)+(Ca[7])) ^ KO83, KI83) ^ X1a;				// FI(X1a ^ CaRR ^ KO83, KI83) ^ X1a	
	u16 Xb = FI(X1b ^ ((u16)(Cb[6]<<8)+(Cb[7])) ^ KO83, KI83) ^ X1b;	
	u16 Xc = FI(X1c ^ ((u16)(Cc[6]<<8)+(Cc[7])) ^ KO83, KI83 ^ 0x8000) ^ X1c;	
	u16 Xd = FI(X1d ^ ((u16)(Cd[6]<<8)+(Cd[7])) ^ KO83, KI83 ^ 0x8000) ^ X1d;	

	u16 Yac = rightRotate(Xa ^ Xc ^ ((u16)(Ca[2]<<8)+(Ca[3])) ^ ((u16)(Cc[2]<<8)+(Cc[3])), 1);	//(Xa ^ Xc ^ CaLR ^ CcLR) >>> 1
	u16 Ybd = rightRotate(Xb ^ Xd ^ ((u16)(Cb[2]<<8)+(Cb[3])) ^ ((u16)(Cd[2]<<8)+(Cd[3])), 1);

	u16 Xac = X1a ^ X1c;
	u16 Xbd = X1b ^ X1d;

	Array a;					// will contain all the duplicates of the key KL81 in case we found {0,1} in the lookup table
	initArray(&a, 4);	
	int KL81 = KL81R;
	insertArray(&a, KL81);

	// For each bit in (Xac, Yac, Xbd, Ybd) find the corresponding value of the key KL82 through the lookup table

	for (int p = 0; p < 16; p++) {
		int b = 0;

		if (p > 7 && p < 15) {
			int i = 0;
			int j = 0;

			if (Xac & 1) i += 2;	// Current bit is set to 1
			if (Yac & 1) i += 1;
			if (Xbd & 1) j += 2;
			if (Ybd & 1) j += 1;

			//printf("p: %d\t", 4*i + j);

			b = AND[4*i + j];
		}

		//printf("b: %d\n", b);

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
				int m = a.array[i];			// n -> KL81[p] = 0
				m = m + pow(2, p);			// m -> KL81[p] = 1
				insertArray(&a, m);
			}
		}
					
		Xac >>= 1;
		Yac >>= 1;
		Xbd >>= 1;
		Ybd >>= 1;
	}

	//printf("\n");

	return a;
}

/*--------------------------------------- SANDWICH -----------------------------------------*/

int main(void) {
	clock_t begin = clock();
	time_t t;
	int exp = 24;
	int nPlaintext = pow(2, exp);       // should be pow(2, 24)
	srand((unsigned) time(&t));    		// Initializes random number generator
	int z = 0;                     		// Initializes the progress bar

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
	
	/*
	for (int i = 0; i < 16; i++) {
		Ka[i] = rand() % 255;     // 255_10 = ff_16 = 11111111_2
	}
	*/

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

			//printHex("Cc", Cc, 8);
			//printHex("Cd", Cd, 8);
			//printHex("index", indexRQ, 4);

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

	printRightQuartetsEntries();
	printf("I have found %d right quartets.\n", HASH_COUNT(rightQuartetsTable));

	u8* rightIndex = rightQuartetsTable -> index;
	struct rightQuartetsEntry *h;
	for (h = rightQuartetsTable; h != NULL; h = h -> hh.next) {
		if (!compareArray(h -> index, rightIndex, 4)) {
			// We have true right quartest with other quartets
			printf("I have found collisions on more that one constant. Can't proceed with the attack.\n");
			//exit(0);
			goto exit;
		}
	}

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
	 * 3. Analyzing Right Quartets:
	 *-------------------------------------------------------------------------------------------*/

	if (HASH_COUNT(rightQuartetsTable) == 0) {
		printf("No right quartet found. Can't proceed with the attack.\n");
		//exit(0);
		goto exit;
	}

	/*-------------------------------------------------------------------------------------------
	 *	(a) For each remaining quartet (C_a, C_b, C_c, C_d), guess the 32-bit value of
	 *		KO_8,1 and KI_8,1 
	 *-------------------------------------------------------------------------------------------*/

	printf("PHASE 3: ANALYZING RIGHT QUARTETS\n");

	int cont = 1;
	u16 KO81, KI81;

	for (q = rightQuartetsTable; q != NULL; q = q->hh.next) {
		printf("Analyzing quartet n. %d\n", cont);

		for (int i = 0; i < 8; i++) {
			Ca[i] = (q -> CaCbCcCd)[i];
			Cb[i] = (q -> CaCbCcCd)[i + 8];
			Cc[i] = (q -> CaCbCcCd)[i + 16];
			Cd[i] = (q -> CaCbCcCd)[i + 24];
		}

		/*
		printHex("index", q -> index, 4);
		printHex("Ca", Ca, 8);				
		printHex("Cb", Cb, 8);
		printHex("Cc", Cc, 8);				
		printHex("Cd", Cd, 8);
		*/

		/*-------------------------------------------------------------------------------------------
		 *		For the two pairs (C_a, C_c) and (C_b, C_d) use the value of the guessed key 
		 *		to compute the input and output diﬀerences of the OR operation in the last 
		 *		round of both pairs. For each bit of this 16-bit OR operation of F L8, 
		 *		the possible values of the corresponding bit of KL 8,2 are given
		 *-------------------------------------------------------------------------------------------*/

		printf("Guessing the keys KO81 and KI81...\n");

		z = 0;	// Initializing the progress bar

		int nSuggestedKeys = 0;

		KO81 = 0x0000;
		KI81 = 0x0000;	

		for (int ko = 0; ko <= 0xffff; ko++) {
			KI81 = 0x0000;
			
			for (int ki = 0; ki <= 0x01ff; ki++) {
				Array a = findKL82R(Ca, Cb, Cc, Cd, KO81, KI81);

				if (a.used > 0) {
					for (int i = 0; i < a.used; i++) {

						if (cont == 1) {									// devo riempire il set di partenza
							addOrREntry(KO81, KI81, a.array[i]);
						} else {											// devo riempire un altro set, dopo di che farò l'intersezione
							if (findOrREntry(KO81, KI81, a.array[i])) {	
								addTmpOrREntry(KO81, KI81, a.array[i]);		// se la tripla è in OrSet, allora la aggiungo ad un nuovo set
							}
						}
						
						nSuggestedKeys++;
					}
				}

				freeArray(&a);
				KI81++;

				if ((u32)((KO81<<16)+(KI81)) > z * (pow(2,32)/100.0)) {
					printProgress(z/100.0);
					z++;
				} else if ((u32)((KO81<<16)+(KI81)) == pow(2,32) - 1) {
					printProgress(1);
				}
			}

			KO81++;
		}
		printf("\n");
		//printf("Suggested keys: \t%d\n", nSuggestedKeys);
		//printf("Keys in the set OR: \t%d\n", HASH_COUNT(OrSet));
		//printf("Keys in the set tmp: \t%d\n", HASH_COUNT(tmpOrSet));
		//printOrEntries();

		if (cont > 1) {
			// assegno ad OrSet il nuovo set provvisorio
			deleteAllOrREntries();

			struct tmpOrREntry *k;
			for (k = tmpOrRSet; k != NULL; k = k -> hh.next) {
				addOrREntry(k -> index[0], k -> index[1], k -> index[2]);
			}

			// libero il set provvisorio
			deleteAllTmpOrREntries();
		}
		
		nSuggestedKeys = 0;
		cont++;
	}

	/*-------------------------------------------------------------------------------------------
	 *		Since all the right quartets suggest the same key, all the wrong keys are discarded
	 * 		and the attacker obtains the correct value of (KO_8,1, KI_8,1, KL_8,2)
	 *-------------------------------------------------------------------------------------------*/

	printf("I have found %d possible values for subkeys KO81, KI81, KL82:\n", HASH_COUNT(OrRSet));
	printOrREntries();

	if (HASH_COUNT(OrRSet) == 0) {
		printf("The found quartets are not right quartets. Cannot proceed with the attack\n");
		goto exit;
	}

	struct OrREntry *or;
	cont = 1;

	// TODO
	for (q = rightQuartetsTable; q != NULL; q = q->hh.next) {
		printf("Analyzing quartet n. %d\n", cont);

		for (int i = 0; i < 8; i++) {
			Ca[i] = (q -> CaCbCcCd)[i];
			Cb[i] = (q -> CaCbCcCd)[i + 8];
			Cc[i] = (q -> CaCbCcCd)[i + 16];
			Cd[i] = (q -> CaCbCcCd)[i + 24];
		}

		for (or = OrRSet; or != NULL; or = or -> hh.next) {					
			for (int ki = 0x0000; ki <= 0x007f; ki++) {

				KI81 = (u16)((ki << 9) + (or -> index[1]));
				KO81 = or -> index[0];
				Array a = findKL82L(Ca, Cb, Cc, Cd, KO81, KI81, or -> index[2]);

				if (a.used > 0) {
					for (int i = 0; i < a.used; i++) {

						if (cont == 1) {									// devo riempire il set di partenza
							addOrEntry(KO81, KI81, a.array[i]);
						} else {											// devo riempire un altro set, dopo di che farò l'intersezione
							if (findOrEntry(KO81, KI81, a.array[i])) {	
								addTmpOrEntry(KO81, KI81, a.array[i]);		// se la tripla è in OrSet, allora la aggiungo ad un nuovo set
							}
						}
						
						//nSuggestedKeys++;
					}
				}

				freeArray(&a);

				/*
				if ((u32)((KO81<<16)+(KI81)) > z * (pow(2,32)/100.0)) {
					printProgress(z/100.0);
					z++;
				} else if ((u32)((KO81<<16)+(KI81)) == pow(2,32) - 1) {
					printProgress(1);
				}
				*/
			}
		}

		if (cont > 1) {
			// assegno ad OrSet il nuovo set provvisorio
			deleteAllOrEntries();

			struct tmpOrEntry *k;
			for (k = tmpOrSet; k != NULL; k = k -> hh.next) {
				addOrEntry(k -> index[0], k -> index[1], k -> index[2]);
			}

			// libero il set provvisorio
			deleteAllTmpOrEntries();
		}
		
		//nSuggestedKeys = 0;
		cont++;
	}

	deleteAllOrREntries();

	printf("I have found %d possible values for subkeys KO81, KI81, KL82:\n", HASH_COUNT(OrSet));
	printOrEntries();

	if (HASH_COUNT(OrSet) == 0) {
		printf("The found quartets are not right quartets. Cannot proceed with the attack\n");
		goto exit;
	}

	/*-------------------------------------------------------------------------------------------
	 *	(b) Guess the 32-bit value of KO_8,3 and KI_8,3
	 *-------------------------------------------------------------------------------------------*/

	// in teoria dovrei prima riordinarli, ma in realtà sono già ordinati come serve a me
	// per ogni combinazione (KL81, KI81)

	cont = 1;
	u16 prevKO81 = 0x0000;
	u16 prevKI81 = 0x0000;
	u16 KO83, KI83;
	struct OrEntry *k;
	int nSuggestedKeys;

	if (OrSet -> index[0] == 0x0000) prevKO81 = 0x0001;
	if (OrSet -> index[1] == 0x0000) prevKI81 = 0x0001;

	for (k = OrSet; k != NULL; k = k -> hh.next) {
		KO81 = k -> index[0];
		KI81 = k -> index[1];

		//KO81 = 0x2013;
		//KI81 = 0x2310;

		if ((KO81 != prevKO81) || (KI81 != prevKI81)) {
			printf("KO81: %04x, KI81: %04x\n", KO81, KI81);
			cont = 1;

			/*-------------------------------------------------------------------------------------------
			 *		compute the input and output diﬀerences of the AND operation in both pairs
					of each quartet. For each bit of the 16-bit AND operation of F L8, 
					the possible values of the corresponding bit of KL_8,1 are given
			 *-------------------------------------------------------------------------------------------*/

			// ho una nuova combinazione di chiavi: per ogni quartetto devo generare tutte le possibili KO83 e KI83 e cercare KL81
			for (q = rightQuartetsTable; q != NULL; q = q->hh.next) {
				printf("Analyzing quartet n. %d\n", cont);

				for (int i = 0; i < 8; i++) {
					Ca[i] = (q -> CaCbCcCd)[i];
					Cb[i] = (q -> CaCbCcCd)[i + 8];
					Cc[i] = (q -> CaCbCcCd)[i + 16];
					Cd[i] = (q -> CaCbCcCd)[i + 24];
				}

				/*
				printHex("index", q -> index, 4);
				printHex("Ca", Ca, 8);				
				printHex("Cb", Cb, 8);
				printHex("Cc", Cc, 8);				
				printHex("Cd", Cd, 8);
				*/

				printf("Guessing the keys KO83 and KI83...\n");

				z = 0;	// Initializing the progress bar
				nSuggestedKeys = 0;

				KO83 = 0x0000;
				KI83 = 0x0000;	

				for (int ko = 0; ko <= 0xffff; ko++) {
					KI83 = 0x0000;
					
					for (int ki = 0; ki <= 0x01ff; ki++) {
						
						Array a = findKL81R(Ca, Cb, Cc, Cd, KO81, KI81, KO83, KI83);
						
						if (a.used > 0) {
							for (int i = 0; i < a.used; i++) {

								//printf("KO81, KI81, KO83, KI83, KL81:\t%04x, %04x, %04x, %04x, %04x\n", KO81, KI81, KO83, KI83, a.array[i]);

								if (cont == 1) {									// devo riempire il set di partenza
									addAndREntry(KO83, KI83, a.array[i]);
								} else {											// devo riempire un altro set, dopo di che farò l'intersezione
									if (findAndREntry(KO83, KI83, a.array[i])) {	
										addTmpAndREntry(KO83, KI83, a.array[i]);		// se la tripla è in OrSet, allora la aggiungo ad un nuovo set
									}
								}
								
								nSuggestedKeys++;
							}
						}

						freeArray(&a);

						KI83++;

						if ((u32)((KO83<<16)+(KI83)) > z * (pow(2,32)/100.0)) {
							printProgress(z/100.0);
							z++;
						} else if ((u32)((KO83<<16)+(KI83)) == pow(2,32) - 1) {
							printProgress(1);
						}
					}

					KO83++;
				}
				printf("\n");
				//printf("Suggested keys: \t%d\n", nSuggestedKeys);
				//printf("Keys in the set AND: \t%d\n", HASH_COUNT(AndSet));
				//printf("Keys in the set tmp: \t%d\n", HASH_COUNT(tmpAndSet));
				//printAndEntries();
				//printTmpAndEntries();

				if (cont > 1) {
					deleteAllAndREntries();

					struct tmpAndREntry *k;

					for (k = tmpAndRSet; k != NULL; k = k -> hh.next) {
						addAndREntry(k -> index[0], k -> index[1], k -> index[2]);
					}

					deleteAllTmpAndREntries();
				}
				
				nSuggestedKeys = 0;
				cont++;
			}

			//printOrEntries();
			printf("Keys in the set AND: \t%d\n", HASH_COUNT(AndRSet));
			printAndREntries();			

			// TODO		

			struct AndREntry *er;
			cont = 1;

			for (q = rightQuartetsTable; q != NULL; q = q -> hh.next) {
				printf("Analyzing quartet n. %d\n", cont);

				for (int i = 0; i < 8; i++) {
					Ca[i] = (q -> CaCbCcCd)[i];
					Cb[i] = (q -> CaCbCcCd)[i + 8];
					Cc[i] = (q -> CaCbCcCd)[i + 16];
					Cd[i] = (q -> CaCbCcCd)[i + 24];
				}

				for (er = AndRSet; er != NULL; er = er -> hh.next) {
					for (int ki = 0; ki <= 0x007f; ki++) {
						
						KI83 = (u16)((ki << 9) + (er -> index[1]));
						KO83 = er -> index[0];

						Array a = findKL81L(Ca, Cb, Cc, Cd, KO81, KI81, KO83, KI83, er -> index[2]);
						
						if (a.used > 0) {
							for (int i = 0; i < a.used; i++) {

								//printf("KO81, KI81, KO83, KI83, KL81:\t%04x, %04x, %04x, %04x, %04x\n", KO81, KI81, KO83, KI83, a.array[i]);

								if (cont == 1) {									// devo riempire il set di partenza
									addAndEntry(KO83, KI83, a.array[i]);
								} else {											// devo riempire un altro set, dopo di che farò l'intersezione
									if (findAndEntry(KO83, KI83, a.array[i])) {	
										addTmpAndEntry(KO83, KI83, a.array[i]);		// se la tripla è in OrSet, allora la aggiungo ad un nuovo set
									}
								}
								
								//nSuggestedKeys++;
							}
						}

						freeArray(&a);

						/*
						if ((u32)((KO83<<16)+(KI83)) > z * (pow(2,32)/100.0)) {
							printProgress(z/100.0);
							z++;
						} else if ((u32)((KO83<<16)+(KI83)) == pow(2,32) - 1) {
							printProgress(1);
						}
						*/
					}
				}

				//deleteAllAndREntries();

				if (cont > 1) {
					deleteAllAndEntries();

					struct tmpAndEntry *k;

					for (k = tmpAndSet; k != NULL; k = k -> hh.next) {
						addAndEntry(k -> index[0], k -> index[1], k -> index[2]);
					}

					deleteAllTmpAndEntries();
				}
				
				nSuggestedKeys = 0;
				cont++;
			}

			printf("Keys in the set AND: \t%d\n", HASH_COUNT(AndSet));
			printAndEntries();	
		}

		deleteAllAndREntries();

		/*-------------------------------------------------------------------------------------------
		 *		the attacker obtains the correct value of (KO_8,3, KI_8,3, KL_8,1)
		 *-------------------------------------------------------------------------------------------*/

		struct OrEntry *o;
		struct AndEntry *a;

		if (HASH_COUNT(AndSet) > 0) {
			for (o = OrSet; o != NULL; o = o -> hh.next) {
				if ((KO81 == o -> index[0]) && (KI81 == o-> index[1])) {
					for (a = AndSet; a != NULL; a = a -> hh.next) {
						addSubkeysEntry(o -> index[0], o -> index[1], o -> index[2], a -> index[0], a -> index[1], a -> index[2]);
					}
				}
			}
		}

		prevKO81 = KO81;
		prevKI81 = KI81;
	}

	deleteAllOrEntries();
	deleteAllAndEntries();
	printf("I have found %d possible values for subkeys KO81, KI81, KL82, KO83, KI83, KL82:\n", HASH_COUNT(SubkeysSet));
	printSubkeysEntries();

	if (HASH_COUNT(SubkeysSet) == 0) {
		printf("The found quartets are not right quartets. Cannot proceed with the attack\n");
		goto exit;
	}

	/*-------------------------------------------------------------------------------------------
	 * 4. Finding the Right Key: (TODO)
	 *-------------------------------------------------------------------------------------------*/

	printf("PHASE 3: FINDING THE RIGHT KEY\n");

	/*-------------------------------------------------------------------------------------------
	 * 	  	For each value of the 96 bits of (KO _8,1, KI 8,1, KO_8,3, KI_8,3, KL_8,1, KL_8,2) 
	 *		suggested in Step 3, guess the remaining 32 bits of the key, and perform 
	 *	 	a trial encryption.
	 *-------------------------------------------------------------------------------------------*/

	u8 P[8], C[8], trialC[8];

	for (int i = 0; i < 8; i++) {
		P[i] = rand() % 255;
	}

	memcpy(C, &P[0], 8*sizeof(*P));
	KeySchedule(Ka);
	Kasumi(C);

	//printHex("Ka", Ka, 16);
	//printHex("P", P, 8);
	//printHex("C", C, 8);

	u16 K3 = 0x0000;
	u16 K5 = 0x0000;
	u8 *guessedKa;
	u16 KC[8] = {
		0x0123, 0x4567, 0x89AB, 0xCDEF, 0xFEDC, 0xBA98, 0x7654, 0x3210 
	};

	struct SubkeysEntry *s;
	cont = 1;

	for (s = SubkeysSet; s != NULL; s = s -> hh.next) {		// (KO81, KI81, KL82, KO83, KI83, KL81)

		printf("Analyzing keys set n. %d\n", cont);
		printf("Guessing the keys K3 and K5...\n");
		z = 0;	// Initializing the progress bar

		for (int k3 = 0; k3 <= 0xffff; k3++) {				// devo usare delle variabili intere e non u16 sennò si azzera prima di finire e va in loop
			for (int k5 = 0x0000; k5 <= 0xffff; k5++) {
				guessedKa = (u8 [16]) {
					rightRotate(s -> index[0], 5) >> 8,		// K1
					rightRotate(s -> index[0], 5) & 0xff,
					(s -> index[2] ^ KC[1]) >> 8,			// K2
					(s -> index[2] ^ KC[1]) & 0xff,		
					K3 >> 8,								// K3
					K3 & 0xff,						
					(s -> index[1] ^ KC[3]) >> 8,			// K4
					(s -> index[1] ^ KC[3]) & 0xff,		
					K5 >> 8,								// K5
					K5 & 0xff,						
					rightRotate(s -> index[3], 13) >> 8,	// K6
					rightRotate(s -> index[3], 13) & 0xff,
					(s -> index[4] ^ KC[6]) >> 8,			// K7
					(s -> index[4] ^ KC[6]) & 0xff,		
					rightRotate(s -> index[5], 1) >> 8,		// K8
					rightRotate(s -> index[5], 1) & 0xff	
				};

				memcpy(trialC, &P[0], 8*sizeof(*P));
				KeySchedule(guessedKa);
				Kasumi(trialC);

				/*
				if ((K3 == 0xccdd) && (K5 == 0x1122)) {
					printHex("guessedKa", guessedKa, 16);
					printHex("P", P, 8);
					printHex("trialC", trialC, 8);
				}
				*/

				if (compareArray(trialC, C, 8)) {
					printHex("\nFOUND KEY Ka", guessedKa, 16);
					//break;
					goto exit;
				}

				if ((u32)((K3<<16)+(K5)) > z * (pow(2,32)/100.0)) {
					printProgress(z/100.0);
					z++;
				} else if ((u32)((K3<<16)+(K5)) == pow(2,32) - 1) {
					printProgress(1);
				}

				K5++;
			}

			K3++;
			K5 = 0x0000;
		}

		printf("\n");
		cont++;
	}

	exit: ;
	clock_t end = clock();
	double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
	printf("Execution time (s): %.2f\n", time_spent);

	if (!getrusage(RUSAGE_SELF, &usage)) {
		printf("Maximum resident set size (GB): %.2f\n", usage.ru_maxrss/1000000.0);
	} else {
		perror("getrusage");
	}
}
