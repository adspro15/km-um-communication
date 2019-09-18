#include "CRT.h"

size_t wcslen(const wchar_t *Str) {

	wchar_t * S = (wchar_t*)Str;

	while (*S != L'\0')
		S++;

	return S - Str;
}

wchar_t* wcschr(const wchar_t *Str, wchar_t Ch) {

	wchar_t * StrPtr = (wchar_t*)Str;

	while (*StrPtr) {

		if (*StrPtr == Ch)
			return StrPtr;
		StrPtr++;
	}

	return 0;
}

wchar_t* wcsrchr(const wchar_t *Str, wchar_t Ch) {

	wchar_t *End = (wchar_t*)(Str + wcslen(Str) + 1);

	while (End != Str) {

		End--;
		if (*End == Ch)
			return End;
	}

	return 0;
}

int wcscmp(const wchar_t *Str1, const wchar_t *Str2) {

	if (Str1 == Str2)
		return 0;

	while (*Str1 == *Str2 && *Str1 != 0)
		Str1++,
		Str2++;

	return (*Str1 - *Str2);
}

int wcsncmp(const wchar_t *S1, const wchar_t *S2, size_t n) {

	if (n == 0)
		return 0;

	unsigned char *			p1 = (unsigned char*)S1;
	unsigned char *			p2 = (unsigned char*)S2;

	for (size_t i = 0; i < n; i++) {

		if (!p1[i] || p1[i] != p2[i])
			return p1[i] - p2[i];
	}

	return 0;
}

wchar_t* wcscpy(wchar_t *Dst, const wchar_t *Src) {

	wchar_t *Ptr = Dst;

	if (Dst == Src)
		return Dst;

	while (*Src != 0) {
		*Ptr = *Src;
		Ptr++;
		Src++;
	}

	*Ptr = L'\0';

	return Dst;
}

wchar_t* wcsdup(const wchar_t *Src) {

	if (!Src)
		return 0;

	wchar_t *Dst = (wchar_t*)malloc((wcslen(Src) + 1) * sizeof(wchar_t));
	wcscpy(Dst, Src);
	return Dst;
}

wchar_t* wcscat(wchar_t *Dst, const wchar_t *Src) {

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

wchar_t * wcsstr(const wchar_t *Str, const wchar_t *SubStr) {

	size_t StrLen = wcslen(Str);
	size_t SubstrLen = wcslen(SubStr);

	if (!SubstrLen)
		return (wchar_t *)Str;

	if (StrLen < SubstrLen)
		return 0;

	for (int i = 0; i < (int)(StrLen - SubstrLen + 1); i++) {

		if (!wcscmp(&Str[i], SubStr))
			return (wchar_t *)(&Str[i]);
	}

	return 0;
}

BOOLEAN AsciiToLowerCaseW(const wchar_t *  Output, const wchar_t * Src) {

	wchar_t * SrcPtr = (wchar_t*)Src;
	wchar_t * OutputPtr = (wchar_t*)Output;

	while (*SrcPtr) {

		if (!__isascii(*SrcPtr))
			return FALSE;

		if (isupper((CHAR)*SrcPtr)) {
			*OutputPtr = (wchar_t)tolower(*SrcPtr);
		}
		else {
			*OutputPtr = *SrcPtr;
		}

		SrcPtr++;
		OutputPtr++;
	}

	*OutputPtr = L'\0';
	return TRUE;
}

BOOLEAN AsciiWideToChar(const char * Output, const  wchar_t * Src) {

	wchar_t * SrcPtr = (wchar_t*)Src;
	char * OutputPtr = (char*)Output;

	while (*SrcPtr) {

		if (!__isascii(*SrcPtr))
			return FALSE;

		*OutputPtr = (char)*SrcPtr;

		SrcPtr++;
		OutputPtr++;
	}

	*OutputPtr = '\0';

	return TRUE;
}