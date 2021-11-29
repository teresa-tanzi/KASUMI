/* https://chowdera.com/2020/12/20201231215025851q.html */

#include <stdio.h>
#include "uthash.h"

struct my_struct {
    int id;            /* we'll use this field as the key */
    char name[10];
    UT_hash_handle hh; /* makes this structure hashable */
};

struct my_struct *users = NULL;

void add_user(int user_id, char *name) {
    struct my_struct *s;

    s = malloc(sizeof(struct my_struct));
    s->id = user_id;
    strcpy(s->name, name);
    HASH_ADD_INT(users, id, s);  /* id: name of key field */
}

struct my_struct *find_user(int user_id) {
    struct my_struct *s;

    HASH_FIND_INT(users, &user_id, s);  /* s: output pointer */
    return s;
}

void delete_user(struct my_struct *user) {
    HASH_DEL(users, user);  /* user: pointer to deletee */
    free(user);             /* optional; it's up to you! */
}

int main(void) {
	struct my_struct *u;

	add_user(0, "aaa");
	add_user(1, "bbb");
	add_user(1, "ccc");

	u = find_user(1);
	printf("%s\n", u->name);

	delete_user(u);
    u = find_user(1);
	printf("%s\n", u->name);

	delete_user(u);
    u = find_user(1);
	if (u) printf("%s\n", u->name);
	else printf("id unknown\n");
}