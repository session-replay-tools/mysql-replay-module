#ifndef  PAIRS_INCLUDED
#define  PAIRS_INCLUDED
#include <xcopy.h>
#define MAX_PASSWORD_LEN 256
#define MAX_USER_LEN 256

typedef struct mysql_user{
	char user[MAX_USER_LEN];
	char password[MAX_PASSWORD_LEN];
	struct mysql_user* next;
}mysql_user;

char *retrieve_user_pwd(char *user);
int retrieve_mysql_user_pwd_info(tc_pool_t *, char *);
void release_mysql_user_pwd_info();

#endif

