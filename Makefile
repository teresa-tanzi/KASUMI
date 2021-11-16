# serve ad automatizzare il corretto aggiornamento di più file che hanno delle dipendenze


CFLAGS := -O2 -Wall -ggdb		# opzioni di compilazione predefinite


#prova: prova.c Kasumi.o
#	gcc $(CFLAGS) $^ -o $@

Rectangle: Rectangle.c Kasumi.o
	gcc $(CFLAGS) $^ -o $@

Kasumi.o: Kasumi.c Kasumi.h
	gcc $(CFLAGS) $< -c -o $@


.PHONY: clean
clean:
	rm -f *.o prova
