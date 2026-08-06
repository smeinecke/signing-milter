#include "lowercase.h"

char *lowercase(char *string)
{
    char   *cp;
    int     ch;

    for (cp = string; (ch = *(unsigned char *) cp) != 0; cp++)
	if (isupper(ch))
	    *(unsigned char *) cp = tolower(ch);
    return (string);
}
