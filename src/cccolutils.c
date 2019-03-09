#include <stdbool.h>
#include <string.h>
#include <krb5.h>


char *get_username_for_realm_c(char *realm) {
    krb5_context kcontext;
    krb5_ccache cache;
    krb5_cccol_cursor cursor;
    char *defname;
    krb5_principal principal;

    if (krb5_init_context(&kcontext)) {
        return NULL;
    }

    if (krb5_cccol_cursor_new(kcontext, &cursor)) {
        krb5_free_context(kcontext);
        return NULL;
    }

    while (!(krb5_cccol_cursor_next(kcontext, cursor, &cache)) && cache != NULL) {
        if (krb5_cc_get_principal(kcontext, cache, &principal)) {
            // No valid principal
            krb5_free_principal (kcontext, principal);
            krb5_cc_close(kcontext, cache);
            continue;
        }

        if (strcmp(principal->realm.data, realm)) {
            // Not the correct realm
            krb5_free_principal (kcontext, principal);
            krb5_cc_close(kcontext, cache);
            continue;
        }

        if (krb5_unparse_name_flags(kcontext, principal, KRB5_PRINCIPAL_UNPARSE_NO_REALM, &defname)) {
            krb5_free_principal (kcontext, principal);
            krb5_cc_close(kcontext, cache);
            continue;
        }

        krb5_free_principal (kcontext, principal);
        krb5_cccol_cursor_free (kcontext, &cursor);
        krb5_cc_close(kcontext, cache);
        krb5_free_context(kcontext);
        return defname;
    }

    krb5_cccol_cursor_free (kcontext, &cursor);
    krb5_free_context(kcontext);
    return NULL;
}


void free_username_c(char *username) {
    free(username);
}


bool has_credentials_c() {
    krb5_context kcontext;

    krb5_ccache cache;
    krb5_cccol_cursor cursor;
    krb5_cc_cursor cache_cursor;
    krb5_creds creds;
    krb5_error_code code;

    if (krb5_init_context(&kcontext)) {
        return false;
    }

    bool found = false;

    if (krb5_cccol_cursor_new(kcontext, &cursor)) {
        krb5_free_context(kcontext);
        return false;
    }

    while (!(krb5_cccol_cursor_next(kcontext, cursor, &cache)) && (cache != NULL)) {
        code = krb5_cc_start_seq_get (kcontext, cache, &cache_cursor);
        
        if (code) break;
        
        while (krb5_cc_next_cred(kcontext, cache, &cache_cursor, &creds) == 0) {
            if (!krb5_is_config_principal(kcontext, creds.server)) {
                found = true;
                krb5_free_cred_contents(kcontext, &creds);
                break;
            }
        }

        krb5_cc_end_seq_get(kcontext, cache, &cache_cursor);
        krb5_cc_close(kcontext, cache);

        if (found) {
            break;
        }
    }

    krb5_cccol_cursor_free(kcontext, &cursor);

    krb5_free_context(kcontext);
    return found;
}

