#ifndef  PROTOCOL_INCLUDED
#define  PROTOCOL_INCLUDED
#include <xcopy.h>
/*
 * We support only mysql 4.1 and later.
 * SSL is not supported here
 */

int is_last_data_packet(unsigned char *payload);
void new_crypt(char *result, const char *password, char *message);
int parse_handshake_init_cont(unsigned char *payload,
        size_t length, char *scramble);
int change_clt_auth_content(unsigned char *payload, 
        int length, char *password, char *message);
int change_clt_second_auth_content(unsigned char *payload,
        size_t length, char *new_content);

#endif   /* ----- #ifndef PROTOCOL_INCLUDED  ----- */

