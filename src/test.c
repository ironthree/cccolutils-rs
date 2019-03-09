#include <stdlib.h>
#include <stdio.h>

#include "cccolutils.c"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("No realm specified. Exiting.\n");
        return EXIT_FAILURE;
    }

    bool authed = has_credentials_c();

    if (!authed) {
        printf("No KRB5 authentication found. Exiting.\n");
        return EXIT_FAILURE;
    } else {
        printf("KRB5 authentication found.\n");
    }

    char *realm = argv[1];
    char *username = get_username_for_realm_c(realm);

    printf("KRB5 username: %s\n", username);

    free_username_c(username);
    return EXIT_SUCCESS;
}
