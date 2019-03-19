#include <stdlib.h>
#include <stdio.h>

#include "cccolutils.h"


int main(int argc, char *argv[]) {
    char *realm;

    if (argc < 2) {
        printf("No realm specified. Testing with NULL.\n");
        realm = NULL;
    } else {
        realm = argv[1];
    }

    bool authenticated = has_credentials_c();

    if (!authenticated) {
        printf("No KRB5 authentication found.\n");
    } else {
        printf("KRB5 authentication found.\n");
    }

    bool authenticated_for_realm = has_credentials_for_realm_c(realm);

    if (!authenticated_for_realm) {
        printf("No KRB5 authentication found for realm %s.\n", realm);
    } else {
        printf("KRB5 authentication found for realm %s.\n", realm);
    }

    char *username = get_username_for_realm_c(realm);

    printf("KRB5 username for realm %s: %s\n", realm, username);

    free_char_array_c(username);
    return EXIT_SUCCESS;
}
