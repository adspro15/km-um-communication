#pragma once

size_t
wcslen(
	const wchar_t *Str
);

wchar_t*
wcschr(
	const wchar_t *Str,
	wchar_t Ch
);

wchar_t*
wcsrchr(
	const wchar_t *Str,
	wchar_t Ch
);

int
wcscmp(
	const wchar_t *Str1,
	const wchar_t *Str2
);

int
wcsncmp(
	const wchar_t *S1,
	const wchar_t *S2,
	size_t n
);

wchar_t*
wcscpy(
	wchar_t *Dst,
	const wchar_t *Src
);

wchar_t*
wcsdup(
	const wchar_t *Src
);

wchar_t*
wcscat(
	wchar_t *Dst,
	const wchar_t *Src
);

wchar_t*
wcsstr(
	const wchar_t *Str,
	const wchar_t *SubStr
);

BOOLEAN
AsciiToLowerCaseW(
	const wchar_t *  Output,
	const wchar_t * Src
);

BOOLEAN
AsciiWideToChar(
	const char * Output,
	const  wchar_t * Src
);

#ifndef RtlStringSizeW
/***/#define RtlStringSizeW(s) ((wcslen(s) + 1) * sizeof(wchar_t))
#endif