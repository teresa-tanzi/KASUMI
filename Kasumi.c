/*-----------------------------------------------------------------------
 *							Kasumi.c
 *-----------------------------------------------------------------------
 *
 * A sample implementation of KASUMI, the core algorithm for the
 * 3GPP Confidentiality and Integrity algorithms.
 *
 * This has been coded for clarity, not necessarily for efficiency.
 *
 * This will compile and run correctly on both Intel (little endian)
 * and Sparc (big endian) machines. (Compilers used supported 32-bit ints).
 *
 * Version 1.1	08 May 2000
 *
 *-----------------------------------------------------------------------*/

#include "Kasumi.h"

/*--------- 16 bit rotate left ------------------------------------------*/

// a<<b: shift a sinistra dei bit di a di tanti posti quanto detto da b
// (u16) casta il risultato del rol in unsigned short
// | fa l'or bit a bit, quindi di fatto stiamo facendo una concatenazione perché facendo gli shift abbiamo aggiunto bit a 0
// ROL16(a,b) fa uno shift circolare a sinistra dei bit di a (lungo 16 bit) di b posti

#define ROL16(a,b) (u16)((a<<b)|(a>>(16-b)))

/*------- unions: used to remove "endian" issues ------------------------*/

// Il tipo di dato union serve per memorizzare (in istanti diversi) oggetti di differenti dimensioni e tipo, con, in comune, il ruolo all’interno del programma.
// Si alloca la memoria per la più grande delle variabili, visto che esse non possono mai essere utilizzate contemporaneamente (la scelta di una esclude automaticamente le altre), 
// condividendo il medesimo spazio di memoria. 

typedef union {
	u32 b32;		// 1 x 4 Byte (32 bit)
	u16 b16[2];		// 2 x 2 Byte (32 bit): array di 2 u16, ovvero 2 unsigned short 
	u8 	b8[4];		// 4 x 1 Byte (32 bit)
} DWORD;			// double word (32 bit)

typedef union {
	u16 b16;		// 1 x 2 Byte (16 bit)
	u8 	b8[2];		// 2 x 1 Byte (16 bit)
} WORD;				// word (16 bit)

/*-------- globals: The subkey arrays -----------------------------------*/

// A static global variable or a function is "seen" only in the file it's declared in.

// KASUMI ha una chiave K a 128 bit (16 Byte) che viene utilizzata per derivare le chiavi di rount, anch'esse da 128 bit (16 Byte).
// Consideriamo la chiave K come concatenazione di 8 valori a 16 bit (2 Byte) K1, ..., K8.	
// Generiamo poi un secondo array di chiavi K1', ..., K8' xorando le chiavi Kj per una costante.
// Le chiavi di round delle varie funzioni vengono generate a partire da queste chiavi, quindi le possiamo vedere come array di 8 valoru a 16 bit.

static u16 KLi1[8], KLi2[8];
static u16 KOi1[8], KOi2[8], KOi3[8];
static u16 KIi1[8], KIi2[8], KIi3[8];

/*---------------------------------------------------------------------
 * FI()
 *		The FI function (fig 3). It includes the S7 and S9 tables.
 *		Transforms a 16-bit value.
 *---------------------------------------------------------------------*/

// FI prende 16 bit di dati di input in e 16 bit di subkey

static u16 FI( u16 in, u16 subkey )
{
	u16 nine, seven;	// sono le due metà diseguali in cui suddividiamo l'input

	// A static variable inside a function keeps its value between invocations.
	// You can define an array without an explicit size for the leftmost dimension if you provide an initializer. The compiler will infer the size from the initializer.

	// S-box

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

	nine = (u16)(in>>7);		// se faccio lo shift a destra sto considerando solamente i 9 bit più significativi (quelli a sinistra)
	seven = (u16)(in&0x7F);		// 7F (hex) = 1111111 (bin). Facendo un and & bit a bit con 1111111 stiamo tenendo solamente i 7 bit meno significativi (quelli a destra)

	/* Now run the various operations */

	// L1 = R0	(Feistel)
	// R1 = S9[L0] xor ZE(R0), dove ZE aggiunge 2 bit 0 nell'estremità più significativa (qui stiamo sempre lavorando su 16 bit, quindi non cambia nulla)
	// R2 = S7[L1] xor TR(R1), dove TR elimina i due bit più significativi (tengo i 7 bit meno significativi)

	nine = (u16)(S9[nine] ^ seven);				// ^: xor
	seven = (u16)(S7[seven] ^ (nine & 0x7F));

	// L2 = R1 xor KIij2
	// R2 = R2 xor KIij1

	seven ^= (subkey>>9);		// xor con i 7 bit più significativi della chiave
	nine ^= (subkey&0x1FF);		// 1FF (hex) = 111111111 (bin). xor con i 9 bit meno significativi della chiave

	// L3 = R2
	// R3 = S9[L2] xor ZE(R2)
	// L4 = S7[L3] xor TR(R3)

	nine = (u16)(S9[nine] ^ seven);
	seven = (u16)(S7[seven] ^ (nine & 0x7F));

	// R4 = R3
	// la funzione ritorna L4||R4 (7 + 9 = 16 bit)

	in = (u16)((seven<<9) + nine);

	return( in );
}

/*---------------------------------------------------------------------
 * FO()
 * The FO() function.
 * Transforms a 32-bit value. Uses <index> to identify the
 * appropriate subkeys to use.
 *---------------------------------------------------------------------*/

// prende 32 bit di dati in input e 2 set di sottochiavi: 48 bit KOi e 48 bit KIi (se abbiamo noto il key schedule separatamente, ci basta avere i)

static u32 FO( u32 in, int index )
{
	u16 left, right;

	/* Split the input into two 16-bit words */

	left = (u16)(in>>16);
	right = (u16) in;		// castando a short elimino direttamente i 16 bit più significativi

	/* Now apply the same basic transformation three times */

	// Rj = FI(Lj-1 xor KOij, KIij) xor Rj-1
	// Lj = Rj-1

	left ^= KOi1[index];
	left = FI( left, KIi1[index] );		// le chiavi sono variabili globaili dichiarate all'inizio, ma quando vengono inizializzate?
	left ^= right;

	right ^= KOi2[index];
	right = FI( right, KIi2[index] );
	right ^= left;

	left ^= KOi3[index];
	left = FI( left, KIi3[index] );
	left ^= right;

	// ritorniamo il valore a 32 bit L3||R3

	in = (((u32)right)<<16)+left;

	return( in );
}

/*---------------------------------------------------------------------
 * FL()
 * The FL() function.
 * Transforms a 32-bit value. Uses <index> to identify the
 * appropriate subkeys to use.
 *---------------------------------------------------------------------*/

// prende in input 32 bit di dati e 32 bit di sottochiave (qui la identifico con l'indice)

static u32 FL( u32 in, int index )
{
	u16 l, r, a, b;

	/* split out the left and right halves */

	l = (u16)(in>>16);
	r = (u16)(in);

	/* do the FL() operations */

	// R' = R xor ROL(L and KLi1)

	a = (u16) (l & KLi1[index]);
	r ^= ROL16(a,1);

	// L' = L xor ROL(R' or KL12)

	b = (u16)(r | KLi2[index]);
	l ^= ROL16(b,1);
	
	/* put the two halves back together */

	// ritorno  L'||R'
	
	in = (((u32)l)<<16) + r;	// faccio spazio a destra per 16 bit a 0, dopo di che basta sommare i 16 bit del lato destro
	
	return( in );
}

/*---------------------------------------------------------------------
 * Kasumi()
 * the Main algorithm (fig 1). Apply the same pair of operations
 * four times. Transforms the 64-bit input.
 *---------------------------------------------------------------------*/

void Kasumi( u8 *data )		// puntatore a char (8 bit), ovvero al primo carattere dell'input (metterò l'input in un array di 64 char)
{
	u32 left, right, temp;
	DWORD *d;				// puntatore a double word (32 bit)
	int n;

	/* Start by getting the data into two 32-bit words (endian corect) */

	d = (DWORD*)data;		// casto ad un puntatore a double word (contiene metà del testo da cifrare)
	left = (((u32)d[0].b8[0])<<24)+(((u32)d[0].b8[1])<<16)+(d[0].b8[2]<<8)+(d[0].b8[3]);	// fa 'sta cosa per riordinare la stringa in base al little endian?
	right = (((u32)d[1].b8[0])<<24)+(((u32)d[1].b8[1])<<16)+(d[1].b8[2]<<8)+(d[1].b8[3]);
	n = 0;
	do{	
		// Ri = Li-1
		// Li = Ri-1 xor fi(Li-1, RKi)

		// fi(i, RKi) = FO(FL(I, KLi), KOi, KIi)	se i dispari

		temp = FL( left, n);
		temp = FO( temp, n++ );
		right ^= temp;

		// fi(i, RKi) = FL(FO(I, KOi, KIi), KLi)	se i pari

		temp = FO( right, n);
		temp = FL( temp, n++ );
		left ^= temp;
	}while( n<=7 );

	/* return the correct endian result */

	// alla fine ritroverò l'output nella stessa zona di memoria dove inizialmente avevo l'input

	d[0].b8[0] = (u8)(left>>24);	d[1].b8[0] = (u8)(right>>24);
	d[0].b8[1] = (u8)(left>>16);	d[1].b8[1] = (u8)(right>>16);
	d[0].b8[2] = (u8)(left>>8);		d[1].b8[2] = (u8)(right>>8);
	d[0].b8[3] = (u8)(left);		d[1].b8[3] = (u8)(right);
}

/*---------------------------------------------------------------------
 * KasumiDecipher()
 * Apply Kasumi functions in reverse
 *---------------------------------------------------------------------*/

void KasumiDecipher( u8 *data )
{
	u32 left, right, temp;
	DWORD *d;
	int n;

	/* Start by getting the data into two 32-bit words (endian corect) */

	d = (DWORD*)data;
	left = (((u32)d[0].b8[0])<<24)+(((u32)d[0].b8[1])<<16)+(d[0].b8[2]<<8)+(d[0].b8[3]);
	right = (((u32)d[1].b8[0])<<24)+(((u32)d[1].b8[1])<<16)+(d[1].b8[2]<<8)+(d[1].b8[3]);
	n = 7;	// utilizzo le chiavi al contrario
	do{	
		// Ri = Li+1
		// Li = Ri+1 xor fi(Li+1, RKi)

		// fi(i, RKi) = FL(FO(I, KOi, KIi), KLi)	se i pari

		temp = FO( right, n);
		temp = FL( temp, n-- );
		left ^= temp;

		// fi(i, RKi) = FO(FL(I, KLi), KOi, KIi)	se i dispari

		temp = FL( left, n);
		temp = FO( temp, n-- );
		right ^= temp;
	}while( n>=0 );

	/* return the correct endian result */

	d[0].b8[0] = (u8)(left>>24);	d[1].b8[0] = (u8)(right>>24);
	d[0].b8[1] = (u8)(left>>16);	d[1].b8[1] = (u8)(right>>16);
	d[0].b8[2] = (u8)(left>>8);		d[1].b8[2] = (u8)(right>>8);
	d[0].b8[3] = (u8)(left);		d[1].b8[3] = (u8)(right);
}

/*---------------------------------------------------------------------
 * KeySchedule()
 * Build the key schedule. Most "key" operations use 16-bit
 * subkeys so we build u16-sized arrays that are "endian" correct.
 *---------------------------------------------------------------------*/

void KeySchedule( u8 *k )	// puntatore al primo char della chiave
{
	static u16 C[] = {		// costanti
		0x0123,0x4567,0x89AB,0xCDEF, 0xFEDC,0xBA98,0x7654,0x3210 
	};
	u16 key[8], Kprime[8];	// la chiave è composta da 128 bit = 8 x 16 bit
	WORD *k16;				// puntatore ad una word da 16 bit
	int n;

	/* Start by ensuring the subkeys are endian correct on a 16-bit basis */

	k16 = (WORD *)k;		// casto ad un puntatore a word (16 bit)
	for( n=0; n<8; ++n )	
		key[n] = (u16)((k16[n].b8[0]<<8) + (k16[n].b8[1]));	// suddivido la chiave in 8 sottochiavi da 16 bit ciascuna 
															// non mi è chiara di come funzioni la gesione dell'endian (?)

	/* Now build the K'[] keys */

	for( n=0; n<8; ++n )
		Kprime[n] = (u16)(key[n] ^ C[n]);

	/* Finally construct the various sub keys */

	// tutte queste variabili erano già state dichiarate all'inizio

	for( n=0; n<8; ++n )
	{
		KLi1[n] = ROL16(key[n],1);
		KLi2[n] = Kprime[(n+2)&0x7];
		KOi1[n] = ROL16(key[(n+1)&0x7],5);
		KOi2[n] = ROL16(key[(n+5)&0x7],8);
		KOi3[n] = ROL16(key[(n+6)&0x7],13);
		KIi1[n] = Kprime[(n+4)&0x7];
		KIi2[n] = Kprime[(n+3)&0x7];
		KIi3[n] = Kprime[(n+7)&0x7];
	}
}

/*---------------------------------------------------------------------
 *				e n d   	o f 	  k a s u m i . c
 *---------------------------------------------------------------------*/