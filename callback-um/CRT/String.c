#include "CRT.h"

size_t strlen(const char *Str) {

	char * S = (char*)Str;

	while (*S != 0)
		S++;

	return S - Str;
}

char *strchr(char const* Str, int Ch) {

	char * StrPtr = (char*)Str;

	while (*StrPtr) {

		if (*StrPtr == Ch)
			return StrPtr;
		StrPtr++;
	}

	return 0;
}

char* strrchr(char const* Str, int Ch) {

	char *End = (char*)(Str + strlen(Str) + 1);

	while (End != Str) {

		End--;
		if (*End == Ch)
			return End;
	}

	return 0;
}

int strcmp(const char *Str1, const char *Str2) {

	if (Str1 == Str2)
		return 0;

	while (*Str1 == *Str2 && *Str1 != 0)
		Str1++,
		Str2++;

	return (*Str1 - *Str2);
}

int strncmp(const char *s1, const char *s2, size_t n) {

	if (n == 0)
		return 0;

	const unsigned char *p1 = (const unsigned char*)s1;
	const unsigned char *p2 = (const unsigned char*)s2;

	for (size_t i = 0; i < n; i++) {

		if (!p1[i] || p1[i] != p2[i])
			return p1[i] - p2[i];
	}

	return 0;
}

char *strcpy(char *DstPtr, const char *SrcPtr) {

	char *Ptr = DstPtr;

	if (DstPtr == SrcPtr)
		return DstPtr;

	while (*SrcPtr != 0) {
		*Ptr = *SrcPtr;
		Ptr++;
		SrcPtr++;
	}

	*Ptr = '\0';

	return DstPtr;
}

char *strdup(const char *Src) {

	if (!Src)
		return 0;

	char *DstPtr = (char*)malloc(strlen(Src) + 1);
	strcpy(DstPtr, Src);

	return DstPtr;
}


char *strcat(char *Dst, const char *Src) {

	while (*Dst != 0)
		Dst++;

	while (*Src != 0) {
		*Dst = *Src;
		Dst++;
		Src++;
	}

	*Dst = 0;

	return Dst;
}

char *strstr(char const* Str, char const* Substr) {

	size_t StrLen = strlen(Str);
	size_t SubstrLen = strlen(Substr);

	if (!SubstrLen)
		return (char *)Str;

	if (StrLen < SubstrLen)
		return 0;

	for (int i = 0; i < (int)(StrLen - SubstrLen + 1); i++) {

		if (!strcmp(&Str[i], Substr))
			return (char *)(&Str[i]);
	}

	return 0;
}

VOID AsciiToLowerCaseA(const char *  Output, const char * Src) {

	char * SrcPtr = (char*)Src;
	char * OutputPtr = (char*)Output;

	while (*SrcPtr) {

		if (isupper((int)*SrcPtr)) {
			*OutputPtr = (char)tolower(*SrcPtr);
		}
		else {
			*OutputPtr = *SrcPtr;
		}
		SrcPtr++;
		OutputPtr++;
	}

	*OutputPtr = '\0';
}

VOID AsciiCharToWide(const wchar_t * Output, const char * Src) {

	char * SrcPtr = (char*)Src;
	wchar_t * OutputPtr = (wchar_t*)Output;

	while (*SrcPtr) {
		*OutputPtr = (wchar_t)*SrcPtr;

		SrcPtr++;
		OutputPtr++;
	}

	*OutputPtr = L'\0';
}
