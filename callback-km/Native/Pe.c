#include "Native.h"

#pragma code_seg(push)
#pragma code_seg("PAGE")

PIMAGE_NT_HEADERS RtlImageNtHeader(PVOID Base) {

	PIMAGE_NT_HEADERS NtHeaders = NULL;

	if (Base != NULL && Base != (PVOID)-1) {

		const PIMAGE_DOS_HEADER DosHeaders = (PIMAGE_DOS_HEADER)Base;

		if (DosHeaders->e_magic == IMAGE_DOS_SIGNATURE) {

			NtHeaders = RvaToVa(PIMAGE_NT_HEADERS, Base, DosHeaders->e_lfanew);

			if (NtHeaders->Signature != IMAGE_NT_SIGNATURE) {

				NtHeaders = NULL;
			}
		}
	}

	return NtHeaders;
}

PVOID LdrFindProcAdressA(const PVOID Base, const char* Name) {

	ANSI_STRING TargetName = { 0 };
	RtlInitAnsiString(&TargetName, Name);

	const PIMAGE_NT_HEADERS NtHeaders = RtlImageNtHeader(Base);

	if (!NtHeaders) {

		return NULL;
	}

	if (IMAGE_DIRECTORY_ENTRY_EXPORT >= NtHeaders->OptionalHeader.NumberOfRvaAndSizes) {

		return NULL;
	}

	const PIMAGE_DATA_DIRECTORY ExportDataDir = &NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	if (!ExportDataDir->VirtualAddress || !ExportDataDir->Size) {

		return NULL;
	}

	const PIMAGE_EXPORT_DIRECTORY ExportDir = RvaToVa(PIMAGE_EXPORT_DIRECTORY, Base, ExportDataDir->VirtualAddress);

	if (!ExportDir->AddressOfNames || !ExportDir->AddressOfNameOrdinals || !ExportDir->AddressOfFunctions) {

		return NULL;
	}

	const PULONG	AddressOfFunctions = RvaToVa(PULONG, Base, ExportDir->AddressOfFunctions);
	const PULONG	AddressOfNames = RvaToVa(PULONG, Base, ExportDir->AddressOfNames);
	const PWORD		Ordinals = RvaToVa(PWORD, Base, ExportDir->AddressOfNameOrdinals);

	for (DWORD i = 0u; i < ExportDir->NumberOfNames; i++) {

		const char* ExportName = RvaToVa(const char*, Base, AddressOfNames[i]);

		ANSI_STRING Export = { 0 };
		RtlInitAnsiString(&Export, ExportName);

		
		if (RtlEqualString(&Export, &TargetName, FALSE)) {

			return RvaToVa(PVOID, Base, AddressOfFunctions[Ordinals[i]]);
		}
	}

	return NULL;
}

PIMAGE_SECTION_HEADER RtlpFindSection(const PVOID Base, const char * SectionName) {

	const PIMAGE_NT_HEADERS NtHeaders = RtlImageNtHeader(Base);

	if (!NtHeaders) {

		return NULL;
	}

	PIMAGE_SECTION_HEADER NtSection;
	NtSection = IMAGE_FIRST_SECTION(NtHeaders);

	ANSI_STRING ASection;
	RtlInitAnsiString(&ASection, SectionName);

	for (ULONG i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++) {

		if (memcmp(SectionName, ASection.Buffer, ASection.Length) == 0) {

			return NtSection;
		}

		++NtSection;
	}

	return NULL;
}

BOOLEAN RtlSectionRange(const PVOID Base, const char * SectionName, PVOID * Min, PVOID * Max) {

	const PIMAGE_NT_HEADERS NtHeaders = RtlImageNtHeader(Base);

	if (!NtHeaders) {

		return FALSE;
	}
	
	PIMAGE_SECTION_HEADER NtSection;

	NtSection = IMAGE_FIRST_SECTION(NtHeaders);

	ANSI_STRING ASection;
	RtlInitAnsiString(&ASection, SectionName);

	for (ULONG i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++) {

		if (memcmp(NtSection->Name, ASection.Buffer, ASection.Length) == 0) {

			if (Min) {

				*Min = RvaToVa(PVOID, Base, NtSection->VirtualAddress);
			}

			if (Max) {

				NtSection++;
				*Max = RvaToVa(PVOID, Base, NtSection->VirtualAddress);
			}
			return TRUE;
		}
		NtSection++;
	}

	return FALSE;
}

PVOID RtlpFindPatternEx(const PBYTE Start, const PBYTE End, const PBYTE Pattern, const size_t PatternLen, const BYTE WildCard) {

	PBYTE ScanPtr = (PBYTE)Start;
	size_t TempMatch = 0;

	while (ScanPtr < End - PatternLen) {

		for (TempMatch = 0; TempMatch < PatternLen; TempMatch++) {

			if (Pattern[TempMatch] != WildCard && ScanPtr[TempMatch] != Pattern[TempMatch]) {

				break;
			}
		}

		if (TempMatch == PatternLen) {

			return ScanPtr;
		}
		ScanPtr++;
	}

	return NULL;
}
#pragma code_seg(pop)