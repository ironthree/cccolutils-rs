#include <stdbool.h>

#ifndef CCCOLUTILS_H
#define CCCOLUTILS_H

char *get_username_for_realm_c(char *realm);
void free_username_c(char *username);
bool has_credentials_c();

#endif
