#include "Native.h"

#pragma code_seg(push)
#pragma code_seg("PAGE")

NTSTATUS
UtQsi(
	DWORD	SystemInformationClass,
	PVOID*	DataOut
) {

	PVOID pData = NULL;
	ULONG InfoLength = 0x8000;
	NTSTATUS Status = STATUS_SUCCESS;

	for (pData = ExAllocatePoolWithTag(NonPagedPool, InfoLength, MEMORY_TAG)
		;
		; pData = ExAllocatePoolWithTag(NonPagedPool, InfoLength, MEMORY_TAG)) {

		if (pData == NULL) {

			return STATUS_NO_MEMORY;
		}

		Status = NtQuerySystemInformation(SystemInformationClass, pData, InfoLength, NULL);

		if (Status != STATUS_INFO_LENGTH_MISMATCH) {

			break;
		}

		ExFreePoolWithTag(pData, MEMORY_TAG);
		InfoLength += 0x8000;
	}

	if (!NT_SUCCESS(Status)) {

		ExFreePoolWithTag(pData, MEMORY_TAG);
		return Status;
	}

	__try {

		*DataOut = pData;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		ExFreePoolWithTag(pData, MEMORY_TAG);
		return GetExceptionCode();
	}

	return STATUS_SUCCESS;
}

NTSTATUS
UtFindProcesses(
	const wchar_t *Name,
	PEPROCESS * OutPr,
	PrCmp_t ProcessCompareFunc
) {

	NTSTATUS Status = STATUS_SUCCESS;

	if (!Name) {

		return STATUS_INVALID_PARAMETER_1;
	}

	UNICODE_STRING TargetName = { 0 };
	RtlInitUnicodeString(&TargetName, Name);

	if (!TargetName.Length) {

		return STATUS_INVALID_PARAMETER_1;
	}

	if (!OutPr) {

		return STATUS_INVALID_PARAMETER_2;
	}

	*OutPr = NULL;
	PVOID pData = NULL;

	Status = UtQsi(0x5, &pData);

	if (!NT_SUCCESS(Status)) {

		return Status;
	}

	PEPROCESS TargetProcess = NULL;

	__try {

		PSYSTEM_PROCESS_INFORMATION pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)pData;

		do {

			if (RtlEqualUnicodeString(&pProcessInfo->ImageName, &TargetName, TRUE)) {

				PEPROCESS TempEprocess = NULL;
				Status = PsLookupProcessByProcessId(pProcessInfo->UniqueProcessId, &TempEprocess);

				if (NT_SUCCESS(Status)) {

					if (ProcessCompareFunc) {

						if (ProcessCompareFunc(
							TempEprocess,
							pProcessInfo->Threads,
							(DWORD_PTR)pProcessInfo + pProcessInfo->NextEntryOffset)
							) {

							TargetProcess = TempEprocess;
							break;
						}
					}
					else {

						TargetProcess = TempEprocess;
						break;
					}
					ObfDereferenceObject(TempEprocess);
				}
			}

			if (!pProcessInfo->NextEntryOffset) {

				break;
			}

			pProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((DWORD_PTR)pProcessInfo + pProcessInfo->NextEntryOffset);

		} while (TRUE);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		DbgPrint("%s:exception 0x%X\n", __FUNCTION__, GetExceptionCode());
	}

	ExFreePoolWithTag(pData, MEMORY_TAG);

	if (TargetProcess == NULL) {

		return STATUS_UNSUCCESSFUL;
	}

	*OutPr = TargetProcess;
	return STATUS_SUCCESS;
}

NTSTATUS
UtFindSystemImage(
	const char* cName,
	PVOID* ImageBase
) {

	ANSI_STRING Name;
	RtlInitAnsiString(&Name, cName);
	NTSTATUS Status = STATUS_SUCCESS;
	PRTL_PROCESS_MODULES pData = NULL;
	
	if (!Name.Length) {

		return STATUS_INVALID_PARAMETER_1;
	}

	if (!ImageBase) {

		return STATUS_INVALID_PARAMETER_2;
	}

	*ImageBase = NULL;

	Status = UtQsi(0xB, (PVOID*)&pData);

	if (!NT_SUCCESS(Status)) {

		return Status;
	}

	PVOID Output = NULL;
	for (ULONG i = 0; i < pData->NumberOfModules; i++) {

		ANSI_STRING Comperand;
		RtlInitAnsiString(&Comperand, (PCSZ)(pData->Modules[i].FullPathName + pData->Modules[i].OffsetToFileName));

		if (RtlEqualString(&Name, &Comperand, TRUE)) {

			Output = pData->Modules[i].ImageBase;
			break;
		}
	}
	
	ExFreePoolWithTag(pData, MEMORY_TAG);

	*ImageBase = Output;
	
	return Output ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

PVOID
UtFindNtos(
	VOID
) {

	PAGED_CODE();
	
	DWORD64 Page = (DWORD64)PAGE_ALIGN(__readmsr(0xC0000082));

	while (*(WORD*)Page != IMAGE_DOS_SIGNATURE && *(DWORD64*)(Page + 0x4E) != 0x6F72702073696854) {

		Page -= PAGE_SIZE;
	}
	
	return (PVOID)Page;
}

#pragma code_seg(pop)