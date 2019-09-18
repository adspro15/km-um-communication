#pragma once

size_t
strlen(
	const char *Str
);

char*
strchr(
	char const* Str,
	int Ch
);

char*
strrchr(
	char const* Str,
	int Ch
);

int
strcmp(
	const char *Str1,
	const char *Str2
);

int
strncmp(
	const char *s1,
	const char *s2,
	size_t n
);

char*
strcpy(
	char *DstPtr,
	const char *SrcPtr
);

char*
strdup(
	const char *Src
);

char*
strcat(
	char *Dst,
	const char *Src
);

char*
strstr(
	char const* Str,
	char const* Substr
);

VOID
AsciiToLowerCaseA(
	const char * Output,
	const char * Src
);

VOID
AsciiCharToWide(
	const wchar_t * Output,
	const char * Src
);

#ifndef RtlStringSizeA
/***/#define RtlStringSizeA(s) ((strlen(s) + 1) * sizeof(char))
#endif