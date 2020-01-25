#include <string.h>
#include <krb5.h>

#include "cccolutils.h"


char *get_username_for_realm_c(char *realm) {
    if (realm == NULL) {
        return NULL;
    }

    krb5_context kcontext = NULL;
    if (krb5_init_context(&kcontext)) {
        return NULL;
    }

    krb5_cccol_cursor cursor = NULL;
    if (krb5_cccol_cursor_new(kcontext, &cursor)) {
        krb5_free_context(kcontext);
        return NULL;
    }

    krb5_ccache cache = NULL;
    while (krb5_cccol_cursor_next(kcontext, cursor, &cache) == 0) {
        if (cache == NULL) {
            break;
        }

        krb5_principal principal = NULL;
        if (krb5_cc_get_principal(kcontext, cache, &principal)) {
            // No valid principal
            krb5_cc_close(kcontext, cache);
            continue;
        }

        if (strcmp(principal->realm.data, realm) != 0) {
            // Not the correct realm
            krb5_free_principal(kcontext, principal);
            krb5_cc_close(kcontext, cache);
            continue;
        }

        char *defname = NULL;
        if (krb5_unparse_name_flags(kcontext, principal, KRB5_PRINCIPAL_UNPARSE_NO_REALM, &defname)) {
            // parsing of the username failed
            krb5_free_principal(kcontext, principal);
            krb5_cc_close(kcontext, cache);
            continue;
        }

        // username successfully determined
        krb5_free_principal(kcontext, principal);
        krb5_cccol_cursor_free(kcontext, &cursor);
        krb5_cc_close(kcontext, cache);
        krb5_free_context(kcontext);

        return defname;
    }

    // no authenticated user found for the given realm
    krb5_cccol_cursor_free(kcontext, &cursor);
    krb5_free_context(kcontext);
    return NULL;
}


void free_char_array_c(char *char_array) {
    if (char_array == NULL)
        return;

    free(char_array);
}


bool has_credentials_for_realm_c(char *realm) {
    krb5_context kcontext = NULL;
    if (krb5_init_context(&kcontext)) {
        return false;
    }

    krb5_cccol_cursor cursor = NULL;
    if (krb5_cccol_cursor_new(kcontext, &cursor)) {
        krb5_free_context(kcontext);
        return false;
    }

    krb5_ccache cache = NULL;
    bool found = false;

    while (krb5_cccol_cursor_next(kcontext, cursor, &cache) == 0) {
        if (cache == NULL) {
            break;
        }

        krb5_cc_cursor cache_cursor = NULL;
        krb5_error_code code = 0;

        code = krb5_cc_start_seq_get(kcontext, cache, &cache_cursor);

        if (code) break;

        krb5_creds credentials;
        while (krb5_cc_next_cred(kcontext, cache, &cache_cursor, &credentials) == 0) {
            if (!krb5_is_config_principal(kcontext, credentials.server)) {
                if ((realm != NULL) && (strcmp(credentials.server->realm.data, realm) != 0)) {
                    // Not the correct realm
                    krb5_free_cred_contents(kcontext, &credentials);
                    continue;
                } else {
                    // Either the realm wasn't specified, or it matched
                    krb5_free_cred_contents(kcontext, &credentials);
                    found = true;
                }
            }

            if (found) break;
        }

        krb5_cc_end_seq_get(kcontext, cache, &cache_cursor);
        krb5_cc_close(kcontext, cache);

        if (found) break;
    }

    krb5_cccol_cursor_free(kcontext, &cursor);
    krb5_free_context(kcontext);
    return found;
}


bool has_credentials_c() {
    return has_credentials_for_realm_c(NULL);
}

