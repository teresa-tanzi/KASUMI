# serve ad automatizzare il corretto aggiornamento di più file che hanno delle dipendenze


CFLAGS := -O2 -Wall -ggdb		# opzioni di compilazione predefinite
#CFLAGS := -O3 -fomit-frame-pointer -funroll-loops		# opzioni di compilazione nel paper
#LIB := `pkg-config --libs --cflags glib-2.0`
LIB := -lm


Sandwich: Sandwich.c Kasumi.o
	gcc $(CFLAGS) $^ -o $@ $(LIB)

#Rectangle: Rectangle.c Kasumi.o
#	gcc $(CFLAGS) $^ -o $@

Kasumi.o: Kasumi.c Kasumi.h
	gcc $(CFLAGS) $< -c -o $@


.PHONY: clean
clean:
	rm -f *.o prova
