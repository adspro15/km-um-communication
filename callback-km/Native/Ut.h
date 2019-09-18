#pragma once
typedef BOOLEAN(__fastcall*PrCmp_t)(PEPROCESS, PSYSTEM_THREAD_INFORMATION, DWORD_PTR);

NTSTATUS
UtQsi(
	DWORD	SystemInformationClass,
	PVOID*	pData
);

NTSTATUS
UtFindProcesses(
	const wchar_t *Name,
	PEPROCESS * OutPr,
	PrCmp_t ProcessCompareFunc
);

NTSTATUS
UtFindSystemImage(
	const char* cName,
	PVOID* ImageBase
);

PVOID
UtFindNtos(
	VOID
);