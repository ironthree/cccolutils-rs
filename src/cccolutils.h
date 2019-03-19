#include <stdbool.h>

#ifndef CCCOLUTILS_H
#define CCCOLUTILS_H

char *get_username_for_realm_c(char *realm);
void free_char_array_c(char *username);
bool has_credentials_c();
bool has_credentials_for_realm_c(char *realm);

#endif
