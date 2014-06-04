#ifndef  PASSWORD_INCLUDED
#define  PASSWORD_INCLUDED

#define SCRAMBLE_LENGTH  20
#define SHA1_HASH_SIZE   20

void scramble(char *to, const char *message, const char *password);

#endif   /* ----- #ifndef PASSWORD_INCLUDED  ----- */

