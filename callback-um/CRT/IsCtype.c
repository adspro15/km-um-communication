#include "CRT.h"

int isspace(int c) { return ((c >= 0x09 && c <= 0x0D) || (c == 0x20)); }

int isupper(int c) { return (c >= 'A' && c <= 'Z'); }

int isalpha(int c) { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'); }

int isdigit(int c) { return (c >= '0' && c <= '9'); }

int isxdigit(int c) { return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'); }

int isalnum(int c) { return isalpha(c) || isdigit(c); }

int isprint(int c) { return c >= ' '; }

int toupper(int c)
{
	if (c < 'a' || c > 'z')
		return c;
	return c - 0x20;
}

int tolower(int c)
{
	if (c < 'A' || c > 'Z')
		return c;
	return c + 0x20;
}