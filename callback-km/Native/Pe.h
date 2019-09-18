#pragma once
#ifndef RvaToVa
/***/#define RvaToVa(Cast,Base,Rel) ((Cast)((DWORD_PTR)(Base) + (DWORD_PTR)(Rel)))
#endif

PIMAGE_NT_HEADERS
RtlImageNtHeader(
	PVOID Base
);

PVOID
LdrFindProcAdressA(
	const PVOID Base,
	const char* Name
);

PIMAGE_SECTION_HEADER
RtlpFindSection(
	const PVOID Base,
	const char*SectionName
);

BOOLEAN
RtlSectionRange(
	const PVOID Base,
	const char*SectionName,
	PVOID * Min,
	PVOID * Max
);

PVOID
RtlpFindPatternEx(
	const PBYTE Start,
	const PBYTE End,
	const PBYTE Pattern,
	const size_t PatternLen,
	const BYTE WildCard
);

#ifndef RtlFindPatternEx
/***/#define RtlFindPatternEx(Start,End,Pattern,WildCard) RtlpFindPatternEx(Start,End,Pattern,_countof(Pattern),WildCard)
#endif