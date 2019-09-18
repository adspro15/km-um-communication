#include "main.h"
#include "dependencies.h"
#include "loop.h"
#include "undocumented_structs.h"
#include "Structs.h"

VOID ReadSharedMemory
(
)
{
	if (sectionHandle)
		return;

	if (SharedSection)
		ZwUnmapViewOfSection(NtCurrentProcess(), SharedSection);

	SIZE_T ulViewSize = 1024 * 10;
	NTSTATUS ntStatus = ZwMapViewOfSection(sectionHandle, NtCurrentProcess(), &SharedSection, 0, ulViewSize, NULL, &ulViewSize, ViewShare, 0, PAGE_READWRITE | PAGE_NOCACHE);
	if (ntStatus != STATUS_SUCCESS)
	{
		DbgPrintEx(0, 0, "ZwMapViewOfSection fail! Status: %p\n", ntStatus);
		ZwClose(sectionHandle);
		return;
	}
}

NTSTATUS CreateSharedMemory
(
)
{
	NTSTATUS Status = STATUS_SUCCESS;
	DbgPrintEx(0, 0, "calling CreateSharedMemory...\n");

	Status = RtlCreateSecurityDescriptor(&SecDescriptor, SECURITY_DESCRIPTOR_REVISION);
	if (!NT_SUCCESS(Status)) {
		DbgPrintEx(0, 0, "RtlCreateSecurityDescriptor failed : %p\n", Status);
		return Status;
	}

	DaclLength = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) * 3 + RtlLengthSid(SeExports->SeLocalSystemSid) + RtlLengthSid(SeExports->SeAliasAdminsSid) +
		RtlLengthSid(SeExports->SeWorldSid);

	Dacl = ExAllocatePoolWithTag(PagedPool, DaclLength, 'lcaD');

	if (Dacl == NULL) {
		return STATUS_INSUFFICIENT_RESOURCES;
		DbgPrintEx(0, 0, "ExAllocatePoolWithTag  failed  : %p\n", Status);
	}

	Status = RtlCreateAcl(Dacl, DaclLength, ACL_REVISION);

	if (!NT_SUCCESS(Status)) {
		ExFreePool(Dacl);
		DbgPrintEx(0, 0, "RtlCreateAcl  failed  : %p\n", Status);
		return Status;
	}

	Status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, FILE_ALL_ACCESS, SeExports->SeWorldSid);

	if (!NT_SUCCESS(Status)) {
		ExFreePool(Dacl);
		DbgPrintEx(0, 0, "RtlAddAccessAllowedAce SeWorldSid failed  : %p\n", Status);
		return Status;
	}

	Status = RtlAddAccessAllowedAce(Dacl,
		ACL_REVISION,
		FILE_ALL_ACCESS,
		SeExports->SeAliasAdminsSid);

	if (!NT_SUCCESS(Status)) {
		ExFreePool(Dacl);
		DbgPrintEx(0, 0, "RtlAddAccessAllowedAce SeAliasAdminsSid failed  : %p\n", Status);
		return Status;
	}

	Status = RtlAddAccessAllowedAce(Dacl,
		ACL_REVISION,
		FILE_ALL_ACCESS,
		SeExports->SeLocalSystemSid);

	if (!NT_SUCCESS(Status)) {
		ExFreePool(Dacl);
		DbgPrintEx(0, 0, "RtlAddAccessAllowedAce SeLocalSystemSid failed  : %p\n", Status);
		return Status;
	}

	Status = RtlSetDaclSecurityDescriptor(&SecDescriptor,
		TRUE,
		Dacl,
		FALSE);

	if (!NT_SUCCESS(Status)) {
		ExFreePool(Dacl);
		DbgPrintEx(0, 0, "RtlSetDaclSecurityDescriptor failed  : %p\n", Status);
		return Status;
	}

	OBJECT_ATTRIBUTES objAttr;
	UNICODE_STRING sectionName;
	RtlInitUnicodeString(&sectionName, SharedSectionName);
	InitializeObjectAttributes(&objAttr, &sectionName, OBJ_CASE_INSENSITIVE, NULL, &SecDescriptor);

	if (!NT_SUCCESS(Status)) {
		DbgPrintEx(0, 0, "last thing  has failed : %p\n", Status);
	}

	LARGE_INTEGER lMaxSize = { 0 };
	lMaxSize.HighPart = 0;
	lMaxSize.LowPart = 1024 * 10;
	Status = ZwCreateSection(&sectionHandle, SECTION_ALL_ACCESS, &objAttr, &lMaxSize, PAGE_READWRITE, SEC_COMMIT, NULL); // Create section with section handle, object attributes, and the size of shared mem struct
	if (!NT_SUCCESS(Status))
	{
		DbgPrintEx(0, 0, "ZwCreateSection failed: %p\n", Status);
		return Status;
	}

	SIZE_T ulViewSize = 1024 * 10;   // &sectionHandle before was here i guess i am correct 
	Status = ZwMapViewOfSection(sectionHandle, NtCurrentProcess(), &SharedSection, 0, ulViewSize, NULL, &ulViewSize, ViewShare, 0, PAGE_READWRITE | PAGE_NOCACHE);
	if (!NT_SUCCESS(Status)) {
		DbgPrintEx(0, 0, "ZwMapViewOfSection fail! Status: %p\n", Status);
		ZwClose(sectionHandle);
		return Status;
	}

	DbgPrintEx(0, 0, "CreateSharedMemory called finished \n");

	ExFreePool(Dacl);

	return Status;
}

NTSTATUS WriteKernelMemory
(
	PEPROCESS ProcessOfTarget,
	PVOID SourceAddress,
	PVOID TargetAddress,
	SIZE_T Size,
	KM_WRITE_REQUEST* pdata
)
{
	PSIZE_T Bytes;
	NTSTATUS status = STATUS_SUCCESS;

	DbgPrintEx(0, 0, "ProcessidOfSource : %u \n", pdata->ProcessidOfSource);

	PEPROCESS ProcessOfSource;
	status = PsLookupProcessByProcessId(pdata->ProcessidOfSource, &ProcessOfSource);
	if (NT_SUCCESS(status)) {
		DbgPrintEx(0, 0, "PsLookupProcessByProcessId has success ProcessOfSource address : %p \n", ProcessOfSource);
	}
	else {
		status = STATUS_ACCESS_DENIED;
		ObDereferenceObject(ProcessOfSource);
		DbgPrintEx(0, 0, "PsLookupProcessByProcessId Failed Error code : %p \n", status);
		return status;
	}

	KAPC_STATE state;
	KeStackAttachProcess((PKPROCESS)ProcessOfSource, &state);
	DbgPrintEx(0, 0, "Calling MmCopyVirtualMemory withtin the source context. \n");
	status = MmCopyVirtualMemory(PsGetCurrentProcess(), SourceAddress, ProcessOfTarget, TargetAddress, Size, KernelMode, &Bytes);
	KeUnstackDetachProcess(&state);

	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(0, 0, "Error Code... %x\n", status);
		DbgPrintEx(0, 0, "MmCopyVirtualMemory_Error =  PsGetCurrentProcess : %p SourceAddress : %p ProcessOfTarget : %p TargetAddress :  %p Size : %x Bytes : %x \n", PsGetCurrentProcess(), SourceAddress, ProcessOfTarget, TargetAddress, Size, Bytes);
	}
	else
	{
		DbgPrintEx(0, 0, "MmCopyVirtualMemory Success! %x\n", status);
		DbgPrintEx(0, 0, "Bytes : %x \n", Bytes);
	}
}

NTSTATUS ReadKernelMemory
(
	PEPROCESS Process,
	PVOID SourceAddress,
	PVOID TargetAddress,
	SIZE_T Size
)
{
	PSIZE_T Bytes;
	NTSTATUS status = STATUS_SUCCESS;

	KAPC_STATE state;
	KeStackAttachProcess((PKPROCESS)Process, &state);
	DbgPrintEx(0, 0, "we are inside the context memory... \n");
	DbgPrintEx(0, 0, "Calling MmCopyVirtualMemory... \n");
	MmCopyVirtualMemory(PsGetCurrentProcess(), SourceAddress, Process, TargetAddress, Size, KernelMode, &Bytes);
	KeUnstackDetachProcess(&state);

	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(0, 0, "Error Code... %x\n", status);
		DbgPrintEx(0, 0, "__MmCopyVirtualMemory Error || Process : %p || SourceAddress : %p || PsGetCurrentProcess() : %p || TargetAddress : %p || Size : %x  Bytes : %x \n", Process, SourceAddress, PsGetCurrentProcess, TargetAddress, Size, Bytes);
	}
	else
	{
		DbgPrintEx(0, 0, "MmCopyVirtualMemory Success! %x\n", status);
		DbgPrintEx(0, 0, "Bytes Read : %u \n", Bytes);
	}
}

ULONG64 GetModuleBasex64
(
	PEPROCESS proc,
	UNICODE_STRING
	module_name
)
{
	PPEB pPeb = PsGetProcessPeb(proc);

	if (!pPeb) {
		DbgPrintEx(0, 0, "Error pPeb not found \n");
		return 0; // failed
	}

	KAPC_STATE state;

	KeStackAttachProcess(proc, &state);

	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;

	if (!pLdr) {
		DbgPrintEx(0, 0, "Error pLdr not found \n");
		KeUnstackDetachProcess(&state);
		return 0; // failed
	}

	for (PLIST_ENTRY list = (PLIST_ENTRY)pLdr->ModuleListLoadOrder.Flink;
		list != &pLdr->ModuleListLoadOrder; list = (PLIST_ENTRY)list->Flink) {
		PLDR_DATA_TABLE_ENTRY pEntry =
			CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);
		if (RtlCompareUnicodeString(&pEntry->BaseDllName, &module_name, TRUE) ==
			0) {
			ULONG64 baseAddr = (ULONG64)pEntry->DllBase;
			KeUnstackDetachProcess(&state);
			return baseAddr;
		}
	}
	DbgPrintEx(0, 0, "Error exiting funcion nothing was found found \n");
	KeUnstackDetachProcess(&state);

	return 0;
}

PVOID g_KernelBase = NULL;
ULONG g_KernelSize = 0;

PMM_UNLOADED_DRIVER MmUnloadedDrivers;
PULONG				MmLastUnloadedDriver;

PVOID ResolveRelativeAddress
(
	_In_ PVOID Instruction,
	_In_ ULONG OffsetOffset,
	_In_ ULONG InstructionSize
)
{
	ULONG_PTR Instr = (ULONG_PTR)Instruction;
	LONG RipOffset = *(PLONG)(Instr + OffsetOffset);
	PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);

	return ResolvedAddr;
}

NTSTATUS BBSearchPattern
(
	IN PCUCHAR pattern,
	IN UCHAR wildcard,
	IN ULONG_PTR len,
	IN const VOID* base,
	IN ULONG_PTR size,
	OUT PVOID* ppFound
)
{
	ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
	if (ppFound == NULL || pattern == NULL || base == NULL)
		return STATUS_INVALID_PARAMETER;

	for (ULONG_PTR i = 0; i < size - len; i++)
	{
		BOOLEAN found = TRUE;
		for (ULONG_PTR j = 0; j < len; j++)
		{
			if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
			{
				found = FALSE;
				break;
			}
		}

		if (found != FALSE)
		{
			*ppFound = (PUCHAR)base + i;
			return STATUS_SUCCESS;
		}
	}

	return STATUS_NOT_FOUND;
}

PVOID GetKernelBase
(
	OUT PULONG pSize
)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG bytes = 0;
	PRTL_PROCESS_MODULES pMods = NULL;
	PVOID checkPtr = NULL;
	UNICODE_STRING routineName;

	if (g_KernelBase != NULL)
	{
		if (pSize)
			*pSize = g_KernelSize;
		return g_KernelBase;
	}

	RtlUnicodeStringInit(&routineName, L"NtOpenFile");

	checkPtr = MmGetSystemRoutineAddress(&routineName);
	if (checkPtr == NULL)
		return NULL;

	status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);
	if (bytes == 0)
	{
		DbgPrintEx(0, 0, "BlackBone: %s: Invalid SystemModuleInformation size\n");
		return NULL;
	}

	pMods = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 0x454E4F45); // 'ENON'
	RtlZeroMemory(pMods, bytes);

	status = ZwQuerySystemInformation(SystemModuleInformation, pMods, bytes, &bytes);

	if (NT_SUCCESS(status))
	{
		PRTL_PROCESS_MODULE_INFORMATION pMod = pMods->Modules;

		for (ULONG i = 0; i < pMods->NumberOfModules; i++)
		{
			if (checkPtr >= pMod[i].ImageBase &&
				checkPtr < (PVOID)((PUCHAR)pMod[i].ImageBase + pMod[i].ImageSize))
			{
				g_KernelBase = pMod[i].ImageBase;
				g_KernelSize = pMod[i].ImageSize;
				if (pSize)
					*pSize = g_KernelSize;
				break;
			}
		}
	}

	if (pMods)
		ExFreePoolWithTag(pMods, 0x454E4F45);

	DbgPrintEx(0, 0, "g_KernelBase : %p\n", g_KernelBase);
	DbgPrintEx(0, 0, "g_KernelSize : %p\n", g_KernelSize);

	return g_KernelBase;
}


NTSTATUS BBScanSection
(
	IN PCCHAR section,
	IN PCUCHAR pattern,
	IN UCHAR wildcard,
	IN ULONG_PTR len,
	OUT PVOID* ppFound
)
{
	ASSERT(ppFound != NULL);
	if (ppFound == NULL)
		return STATUS_INVALID_PARAMETER;

	PVOID base = GetKernelBase(NULL);
	if (!base)
		return STATUS_NOT_FOUND;

	PIMAGE_NT_HEADERS64 pHdr = RtlImageNtHeader(base);
	if (!pHdr)
		return STATUS_INVALID_IMAGE_FORMAT;

	PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)(pHdr + 1);
	for (PIMAGE_SECTION_HEADER pSection = pFirstSection; pSection < pFirstSection + pHdr->FileHeader.NumberOfSections; pSection++)
	{
		ANSI_STRING s1, s2;
		RtlInitAnsiString(&s1, section);
		RtlInitAnsiString(&s2, (PCCHAR)pSection->Name);
		if (RtlCompareString(&s1, &s2, TRUE) == 0)
		{
			PVOID ptr = NULL;
			NTSTATUS status = BBSearchPattern(pattern, wildcard, len, (PUCHAR)base + pSection->VirtualAddress, pSection->Misc.VirtualSize, &ptr);
			if (NT_SUCCESS(status))
				*(PULONG)ppFound = (ULONG)((PUCHAR)ptr - (PUCHAR)base);

			return status;
		}
	}

	return STATUS_NOT_FOUND;
}

NTSTATUS FindMmDriverData
(
	VOID
)
{
	UCHAR MmLastUnloadedDrivers_sig[] = "\x8B\x05\xCC\xCC\xCC\xCC\x83\xF8\x32";

	UINT64 MmLastUnloadedDriversPtr = NULL;
	if (!NT_SUCCESS(BBScanSection("PAGE", MmLastUnloadedDrivers_sig, 0xCC, sizeof(MmLastUnloadedDrivers_sig) - 1, (UINT64*)(&MmLastUnloadedDriversPtr)))) {
		DbgPrintEx(0, 0, "Unable to find MmLastUnloadedDriversPtr sig.\n");
		return FALSE;
	}

	DbgPrintEx(0, 0, "MmLastUnloadedDriversPtr func address : %p  \n", MmLastUnloadedDriversPtr);

	RtlZeroMemory(MmLastUnloadedDrivers_sig, sizeof(MmLastUnloadedDrivers_sig) - 1);

	// ida pattern : 48 8B 05 ? ? ? ? 48 8D 1C D0
	UCHAR MmUnloadedDrivers_sig[] = "\x48\x8B\x05\xCC\xCC\xCC\xCC\x48\x8D\x1C\xD0";
	UINT64 MmUnloadedDriversPtr = NULL;


	if (!NT_SUCCESS(BBScanSection("PAGE", MmUnloadedDrivers_sig, 0xCC, sizeof(MmUnloadedDrivers_sig) - 1, (UINT64*)(&MmUnloadedDriversPtr)))) {
		DbgPrintEx(0, 0, "Unable to find MmUnloadedDriversPtr sig.\n");
		return FALSE;
	}
	DbgPrintEx(0, 0, "MmUnloadedDriversPtr func address : %p  \n", MmUnloadedDriversPtr);

	RtlZeroMemory(MmUnloadedDrivers_sig, sizeof(MmUnloadedDrivers_sig) - 1);

	UINT64 realPtrMmunloadedDrivers = NULL;

	realPtrMmunloadedDrivers = (UINT64)g_KernelBase + MmUnloadedDriversPtr;
	DbgPrintEx(0, 0, "realPtrMmunloadedDrivers function address : %p\n", realPtrMmunloadedDrivers);
	MmUnloadedDrivers = *(PMM_UNLOADED_DRIVER*)ResolveRelativeAddress(realPtrMmunloadedDrivers, 3, 7);
	DbgPrintEx(0, 0, "MmUnloadedDrivers relative address is: %p  \n", MmUnloadedDrivers);

	UINT64 realPtrMmLastUnloadedDrivers = NULL;

	realPtrMmLastUnloadedDrivers = (UINT64)g_KernelBase + MmLastUnloadedDriversPtr;
	DbgPrintEx(0, 0, "realPtrMmLastUnloadedDrivers function address : %p\n", realPtrMmLastUnloadedDrivers);
	MmLastUnloadedDriver = (PULONG)ResolveRelativeAddress(realPtrMmLastUnloadedDrivers, 2, 6);
	DbgPrintEx(0, 0, "MmLastUnloadedDriver relative address is: %p  \n", MmLastUnloadedDriver);

	return STATUS_SUCCESS;
}

BOOLEAN IsUnloadedDriverEntryEmpty(_In_ PMM_UNLOADED_DRIVER Entry)
{
	if (Entry->Name.MaximumLength == 0 ||
		Entry->Name.Length == 0 ||
		Entry->Name.Buffer == NULL)
	{
		return TRUE;
	}

	return FALSE;
}

BOOLEAN IsMmUnloadedDriversFilled(VOID)
{
	for (ULONG Index = 0; Index < MM_UNLOADED_DRIVERS_SIZE; ++Index)
	{
		PMM_UNLOADED_DRIVER Entry = &MmUnloadedDrivers[Index];
		if (IsUnloadedDriverEntryEmpty(Entry))
		{
			return FALSE;
		}
	}

	return TRUE;
}


NTSTATUS ClearUnloadedDriver(_In_ PUNICODE_STRING	DriverName, _In_ BOOLEAN	 AccquireResource)
{
	if (AccquireResource)
	{
		ExAcquireResourceExclusiveLite(&PsLoadedModuleResource, TRUE);
	}

	BOOLEAN Modified = FALSE;
	BOOLEAN Filled = IsMmUnloadedDriversFilled();

	for (ULONG Index = 0; Index < MM_UNLOADED_DRIVERS_SIZE; ++Index)
	{
		PMM_UNLOADED_DRIVER Entry = &MmUnloadedDrivers[Index];
		if (Modified)
		{
			PMM_UNLOADED_DRIVER PrevEntry = &MmUnloadedDrivers[Index - 1];
			RtlCopyMemory(PrevEntry, Entry, sizeof(MM_UNLOADED_DRIVER));

			if (Index == MM_UNLOADED_DRIVERS_SIZE - 1)
			{
				RtlFillMemory(Entry, sizeof(MM_UNLOADED_DRIVER), 0);
			}
		}
		else if (RtlEqualUnicodeString(DriverName, &Entry->Name, TRUE))
		{
			PVOID BufferPool = Entry->Name.Buffer;
			RtlFillMemory(Entry, sizeof(MM_UNLOADED_DRIVER), 0);
			ExFreePoolWithTag(BufferPool, 'TDmM');

			*MmLastUnloadedDriver = (Filled ? MM_UNLOADED_DRIVERS_SIZE : *MmLastUnloadedDriver) - 1;
			Modified = TRUE;
		}
	}

	if (Modified)
	{
		ULONG64 PreviousTime = 0;

		for (LONG Index = MM_UNLOADED_DRIVERS_SIZE - 2; Index >= 0; --Index)
		{
			PMM_UNLOADED_DRIVER Entry = &MmUnloadedDrivers[Index];
			if (IsUnloadedDriverEntryEmpty(Entry))
			{
				continue;
			}

			if (PreviousTime != 0 && Entry->UnloadTime > PreviousTime)
			{
				Entry->UnloadTime = PreviousTime - 100;
			}

			PreviousTime = Entry->UnloadTime;
		}

		ClearUnloadedDriver(DriverName, FALSE);
	}

	if (AccquireResource)
	{
		ExReleaseResourceLite(&PsLoadedModuleResource);
	}

	return Modified ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

BOOLEAN LocatePiDDB(PERESOURCE* lock, PRTL_AVL_TABLE* table)
{
	UCHAR PiDDBLockPtr_sig[] = "\x48\x8D\x0D\xCC\xCC\xCC\xCC\xE8\xCC\xCC\xCC\xCC\x48\x8B\x0D\xCC\xCC\xCC\xCC\x33\xDB";
	UCHAR PiDTablePtr_sig[] = "\x48\x8D\x0D\xCC\xCC\xCC\xCC\xE8\xCC\xCC\xCC\xCC\x3D\xCC\xCC\xCC\xCC\x0F\x83\xCC\xCC\xCC\xCC";

	UINT64 PiDDBLockPtr = NULL;
	if (!NT_SUCCESS(BBScanSection("PAGE", PiDDBLockPtr_sig, 0xCC, sizeof(PiDDBLockPtr_sig) - 1, (UINT64*)(&PiDDBLockPtr)))) {
		DbgPrintEx(0, 0, "Unable to find PiDDBLockPtr sig.\n");
		return FALSE;
	}
	DbgPrintEx(0, 0, "Ok PiDDBLockPtr sig was found : %p  \n", PiDDBLockPtr);

	RtlZeroMemory(PiDDBLockPtr_sig, sizeof(PiDDBLockPtr_sig) - 1);

	UINT64 PiDTablePtr = NULL;
	if (!NT_SUCCESS(BBScanSection("PAGE", PiDTablePtr_sig, 0xCC, sizeof(PiDTablePtr_sig) - 1, (UINT64*)(&PiDTablePtr)))) {
		DbgPrintEx(0, 0, "Unable to find PiDTablePtr sig.\n");
		return FALSE;
	}
	DbgPrintEx(0, 0, "Ok PiDTablePtr sig was found : %p  \n", PiDTablePtr);

	RtlZeroMemory(PiDTablePtr_sig, sizeof(PiDTablePtr_sig) - 1);

	UINT64 RealPtrPIDLock = NULL;

	RealPtrPIDLock = (UINT64)g_KernelBase + PiDDBLockPtr;

	DbgPrintEx(0, 0, "RealPtrPIDLock :%p\n", RealPtrPIDLock);


	*lock = (PERESOURCE)ResolveRelativeAddress(RealPtrPIDLock, 3, 7);

	UINT64 RealPtrPIDTable = NULL;

	RealPtrPIDTable = (UINT64)g_KernelBase + PiDTablePtr;

	DbgPrintEx(0, 0, "RealPtrPIDTable :%p\n", RealPtrPIDTable);

	*table = (PRTL_AVL_TABLE)(ResolveRelativeAddress(RealPtrPIDTable, 3, 7));

	return TRUE;
}

VOID DriverLoop() {

	while (TRUE)
	{
		DbgPrintEx(0, 0, "running waiting for a command to execute.. \n");
		ReadSharedMemory();
		if (strcmp((PCHAR)SharedSection, "Stop") == 0) {
			DbgPrintEx(0, 0, "breaking out of the loop\n");
			break;
		}
		while (!(PCHAR)SharedSection == NULL && strcmp((PCHAR)SharedSection, "Write") == 0)
		{
			DbgPrintEx(0, 0, "Writing memory loop is running\n");

			KeSetEvent(SharedEvent_dt, 0, FALSE);

			LARGE_INTEGER Timeout;
			Timeout.QuadPart = RELATIVE(SECONDS(1));
			KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
			ReadSharedMemory();

			KM_WRITE_REQUEST* WriteInput = (KM_WRITE_REQUEST*)SharedSection;
			PEPROCESS Process;
			NTSTATUS Status = STATUS_SUCCESS;

			Status = PsLookupProcessByProcessId(WriteInput->ProcessId, &Process);
			if (NT_SUCCESS(Status)) {
				DbgPrintEx(0, 0, "PsLookupProcessByProcessId has success! : %p \n", Status);
				DbgPrintEx(0, 0, "Writing memory.\n");
				WriteKernelMemory(Process, WriteInput->SourceAddress, WriteInput->TargetAddress, WriteInput->Size, WriteInput);
			}
			else {
				Status = STATUS_ACCESS_DENIED;
				ObDereferenceObject(Process);
				DbgPrintEx(0, 0, "PsLookupProcessByProcessId Failed Error code : %p \n", Status);
				return Status;
			}

			KeResetEvent(SharedEvent_dt);
			KeSetEvent(SharedEvent_trigger, 0, FALSE);
			break;
		}

		while (!(PCHAR)SharedSection == NULL && strcmp((PCHAR)SharedSection, "Read") == 0) {
			DbgPrintEx(0, 0, "Read memory loop is running\n");

			KeSetEvent(SharedEvent_dt, 0, FALSE);

			LARGE_INTEGER Timeout;
			Timeout.QuadPart = RELATIVE(SECONDS(1));
			KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
			ReadSharedMemory();

			KM_READ_REQUEST* ReadInput = (KM_READ_REQUEST*)SharedSection;
			void* ReadOutput = NULL;
			PEPROCESS Process;
			NTSTATUS Status = STATUS_SUCCESS;

			DbgPrintEx(0, 0, "ReadInput : %p PID : %u SourceAddress : %p ReadOutput : %p Size : %x \n", ReadInput, ReadInput->ProcessId, ReadInput->SourceAddress, ReadOutput, ReadInput->Size);
			DbgPrintEx(0, 0, "(Before mmcopyvirtualmemory) ReadOutput : %p \n", ReadOutput);

			Status = PsLookupProcessByProcessId(ReadInput->ProcessId, &Process);
			if (NT_SUCCESS(Status)) {
				DbgPrintEx(0, 0, "PsLookupProcessByProcessId has success! : %p \n", Status);
				DbgPrintEx(0, 0, "ReadKernelMemory will be called now !.\n");
				ReadKernelMemory(Process, ReadInput->SourceAddress, &ReadOutput, ReadInput->Size);
			}
			else {
				Status = STATUS_ACCESS_DENIED;
				ObDereferenceObject(Process);
				DbgPrintEx(0, 0, "PsLookupProcessByProcessId Failed Error code : %p \n", Status);
				return Status;
			}

			ReadInput->Output = ReadOutput;

			ReadSharedMemory();
			if (0 == memcpy(SharedSection, ReadInput, sizeof(KM_READ_REQUEST))) {
				DbgPrintEx(0, 0, "memcpy failed \n");
			}

			KeSetEvent(SharedEvent_ReadyRead, 0, FALSE);
			KeResetEvent(SharedEvent_dt);
			KeResetEvent(SharedEvent_ReadyRead);
			KeSetEvent(SharedEvent_trigger, 0, FALSE);
			break;
		}

		while (!(PCHAR)SharedSection == NULL && strcmp((PCHAR)SharedSection, "Clearmm") == 0) {
			DbgPrintEx(0, 0, "Clear Mmunloaded Drivers memory loop is running\n");


			LARGE_INTEGER Timeout;
			Timeout.QuadPart = RELATIVE(SECONDS(1));
			KeDelayExecutionThread(KernelMode, FALSE, &Timeout);

			FindMmDriverData();

			DbgPrintEx(0, 0, "MMunload cleared check with lm command\n");
		}

		while (!(PCHAR)SharedSection == NULL && strcmp((PCHAR)SharedSection, "getBase") == 0) {
			DbgPrintEx(0, 0, "getBase loop is running\n");

			KeSetEvent(SharedEvent_dt, 0, FALSE);

			LARGE_INTEGER Timeout;
			Timeout.QuadPart = RELATIVE(SECONDS(1));
			KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
			ReadSharedMemory();

			GET_USERMODULE_IN_PROCESS* getbase = (GET_USERMODULE_IN_PROCESS*)SharedSection;

			NTSTATUS status = STATUS_SUCCESS;
			PEPROCESS TargetProcess;
			status = PsLookupProcessByProcessId(getbase->pid, &TargetProcess);
			if (!NT_SUCCESS(status)) {
				DbgPrintEx(0, 0, "PsLookupProcessByProcessId failed\n");
			}
			else
			{
				DbgPrintEx(0, 0, "PsLookupProcessByProcessId Success!\n");
			}

			UNICODE_STRING DLLName;
			RtlInitUnicodeString(&DLLName, L"dummy.exe");
			getbase->BaseAddress = GetModuleBasex64(TargetProcess, DLLName);


			DbgPrintEx(0, 0, "getbase->BaseAddress is : %p \n", getbase->BaseAddress);

			ReadSharedMemory();

			if (0 == memcpy(SharedSection, getbase, sizeof(GET_USERMODULE_IN_PROCESS))) {
				DbgPrintEx(0, 0, "memcpy failed \n");
			}

			KeSetEvent(SharedEvent_ReadyRead, 0, FALSE);
			KeResetEvent(SharedEvent_dt);
			KeResetEvent(SharedEvent_ReadyRead);
		}


		while (!(PCHAR)SharedSection == NULL && strcmp((PCHAR)SharedSection, "Clearpid") == 0) {
			DbgPrintEx(0, 0, "Clearpid loop is running\n");

			KeSetEvent(SharedEvent_dt, 0, FALSE);

			LARGE_INTEGER Timeout;
			Timeout.QuadPart = RELATIVE(SECONDS(1));
			KeDelayExecutionThread(KernelMode, FALSE, &Timeout);

			PERESOURCE PiDDBLock = NULL;
			PRTL_AVL_TABLE PiDDBCacheTable = NULL;
			if (!LocatePiDDB(&PiDDBLock, &PiDDBCacheTable) && PiDDBLock == NULL && PiDDBCacheTable == NULL) {
				DbgPrintEx(0, 0, "LocatePiDDB() failed..\n");

				ReadSharedMemory();
				PCHAR TestString = "failed2clear";
				if (0 == memcpy(SharedSection, TestString, 12)) {
					DbgPrintEx(0, 0, "memcpy failed \n");
				}
				else
				{
					DbgPrintEx(0, 0, "Sent ClearPID_fail msg\n");
					KeSetEvent(SharedEvent_ReadyRead, 0, FALSE);
				}
				KeResetEvent(SharedEvent_ReadyRead);
				return STATUS_UNSUCCESSFUL;
			}
			else
			{
				DbgPrintEx(0, 0, "LocatePiDDB() SUCCESS!!!!!..\n");
				DbgPrintEx(0, 0, "PiDDBLock :%p \n", PiDDBLock);
				DbgPrintEx(0, 0, "PiDDBCacheTable :%p\n", PiDDBCacheTable);

				PIDCacheobj lookupEntry;

				UNICODE_STRING DriverName = RTL_CONSTANT_STRING(L"Capcom.sys");

				lookupEntry.DriverName = DriverName;
				lookupEntry.TimeDateStamp = 0x57CD1415;

				ExAcquireResourceExclusiveLite(PiDDBLock, TRUE);

				PIDCacheobj* pFoundEntry = (PIDCacheobj*)RtlLookupElementGenericTableAvl(PiDDBCacheTable, &lookupEntry);
				if (pFoundEntry == NULL)
				{
					DbgPrintEx(0, 0, "pFoundEntry == NULL\n");
					// release the ddb resource lock
					ExReleaseResourceLite(PiDDBLock);
					return 0;
				}
				else
				{
					DbgPrintEx(0, 0, "pFoundEntry Found!\n");

					RemoveEntryList(&pFoundEntry->List);

					RtlDeleteElementGenericTableAvl(PiDDBCacheTable, pFoundEntry);

					ExReleaseResourceLite(PiDDBLock);

					ReadSharedMemory();
					PCHAR pidstring = "ClearedPID";
					if (0 == memcpy(SharedSection, pidstring, 10)) {
						DbgPrintEx(0, 0, "memcpy failed \n");
					}
					else
					{
						DbgPrintEx(0, 0, "Sent clearedpid msg\n");
						KeSetEvent(SharedEvent_ReadyRead, 0, FALSE);
					}
				}
			}

			KeResetEvent(SharedEvent_dt);
			KeResetEvent(SharedEvent_ReadyRead);
		}

		while (!(PCHAR)SharedSection == NULL && strcmp((PCHAR)SharedSection, "Clearmm") == 0) {

			DbgPrintEx(0, 0, "Clearmm loop is running\n");

			KeSetEvent(SharedEvent_dt, 0, FALSE);

			LARGE_INTEGER Timeout;
			Timeout.QuadPart = RELATIVE(SECONDS(1));
			KeDelayExecutionThread(KernelMode, FALSE, &Timeout);

			FindMmDriverData();

			UNICODE_STRING DriverName = RTL_CONSTANT_STRING(L"Capcom.sys");
			if (!NT_SUCCESS(ClearUnloadedDriver(&DriverName, TRUE))) {
				DbgPrintEx(0, 0, "ClearUnloadedDriver failed.\n");
			}
			else
			{
				ReadSharedMemory();
				PCHAR TestString = "Cleared";
				if (0 == memcpy(SharedSection, TestString, 7)) {
					DbgPrintEx(0, 0, "memcpy failed \n");
				}
				else
				{
					DbgPrintEx(0, 0, "Sent Clear msg\n");
					KeSetEvent(SharedEvent_ReadyRead, 0, FALSE);
				}

				DbgPrintEx(0, 0, "ClearUnloadedDriver SUCCESS!.\n");
			}

			KeResetEvent(SharedEvent_dt);
			KeResetEvent(SharedEvent_ReadyRead);
		}
		LARGE_INTEGER Timeout;
		Timeout.QuadPart = RELATIVE(SECONDS(1));
		KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
	}
}

VOID OpenEvents() {

	NTSTATUS status = STATUS_SUCCESS;

	RtlInitUnicodeString(&EventName_dt, L"\\BaseNamedObjects\\DataArrived");
	SharedEvent_dt = IoCreateNotificationEvent(&EventName_dt, &SharedEventHandle_dt);
	if (SharedEvent_dt == NULL) {
		DbgPrintEx(0, 0, "It didn't work lol ! \n", status);
		return STATUS_UNSUCCESSFUL;
	}

	RtlInitUnicodeString(&EventName_trigger, L"\\BaseNamedObjects\\trigger");
	SharedEvent_trigger = IoCreateNotificationEvent(&EventName_trigger, &SharedEventHandle_trigger);
	if (SharedEvent_trigger == NULL) {
		DbgPrintEx(0, 0, "It didn't work lol ! \n", status);
		return STATUS_UNSUCCESSFUL;
	}

	RtlInitUnicodeString(&EventName_ReadyRead, L"\\BaseNamedObjects\\ReadyRead");
	SharedEvent_ReadyRead = IoCreateNotificationEvent(&EventName_ReadyRead, &SharedEventHandle_ReadyRead);
	if (SharedEvent_ReadyRead == NULL) {
		DbgPrintEx(0, 0, "It didn't work lol ! \n", status);
		return STATUS_UNSUCCESSFUL;
	}
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryPath) {
	NTSTATUS status = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER(pRegistryPath);

	DbgPrintEx(0, 0, "Driver loaded !!\n");

	pDriverObject->DriverUnload = DriverUnload;

	CreateSharedMemory();

	OpenEvents();

	DriverLoop();

	DbgPrintEx(0, 0, "driver entry completed!\n");

	return STATUS_SUCCESS;
}

VOID DriverUnload(IN PDRIVER_OBJECT pDriverObject) {

	DbgPrintEx(0, 0, "Driver Unloading routine called! \n");

	if (SharedSection)
		ZwUnmapViewOfSection(NtCurrentProcess(), SharedSection);

	if (sectionHandle)
		ZwClose(sectionHandle);
}
