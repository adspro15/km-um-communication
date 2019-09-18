#include "stdafx.h"
#include "CvcSv/Cvc.h"

HANDLE g_hCvcMainThread = NULL;

#pragma code_seg(push)
#pragma code_seg("PAGE")

VOID
DriverUnload(
	PDRIVER_OBJECT pDriverObject
) {

	UNREFERENCED_PARAMETER(pDriverObject);
	PAGED_CODE();

	CvcClosure = TRUE;

	KeWaitForSingleObject(
		g_hCvcMainThread,
		Executive,
		KernelMode,
		FALSE,
		NULL
	);

	ObDereferenceObject(g_hCvcMainThread);
	g_hCvcMainThread = NULL;

	DbgPrint("Driver unload\n");
}

#pragma code_seg(pop)

#pragma code_seg(push)
#pragma code_seg("INIT")

NTSTATUS
DriverEntry(
	PDRIVER_OBJECT pDriverObject,
	PUNICODE_STRING pRegistryPath
) {

	UNREFERENCED_PARAMETER(pRegistryPath);
	PAGED_CODE();
	DbgPrint("Driver load\n");

	pDriverObject->DriverUnload = &DriverUnload;

	NTSTATUS Status = CvcInitInternals();

	if (!NT_SUCCESS(Status)) {

		DbgPrint("CvcInitInternals function failed 0x%X", Status);
		return STATUS_UNSUCCESSFUL;
	}

	CvcClosure = FALSE;
	HANDLE hCvcMainThread = NULL;

	Status = PsCreateSystemThread(
		&hCvcMainThread,
		GENERIC_ALL,
		NULL,
		NULL,
		NULL,
		CvcMain,
		NULL
	);
	
	if (!NT_SUCCESS(Status)) {

		DbgPrint("Start CvcMain function failed 0x%X", Status);
		return STATUS_UNSUCCESSFUL;
	}

	Status = ObReferenceObjectByHandle(
		hCvcMainThread,
		THREAD_ALL_ACCESS,
		NULL,
		KernelMode,
		&g_hCvcMainThread,
		NULL
	);

	if (!NT_SUCCESS(Status)) {

		DbgPrint("Referencing CvcMain thread failed 0x%X", Status);
		CvcClosure = TRUE;
	}

	return STATUS_SUCCESS;
}
#pragma code_seg(pop)