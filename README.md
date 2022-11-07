# sandwich-attack--KASUMI
Implementation of the Sandwich Attack on the KASUMI cipher [Dunkelman et al. 2010]. Project for my master thesis in Computer Science, a.y. 2022

This repository contains the following files:
- Kasumi.c and Kasumi.h: implementation of the cipher KASUMI according to the official release with minor changes.
- SandwichMultipleHash.c: implementation of the Sandwich Attack with the optimization proposed for the Rectangle Attack [Biham et al. 2005].
- FindRightQuartets.c: experiment containing only the first part of the attack, used for testing purposes.
- uthash.h: C implementation for hash tables (https://troydhanson.github.io/uthash/)
- Makefile: make file used to compile the attack.
- Presentazione.pdf: presentation I used to expose my thesis to the commission.

This attack is only a demo.
