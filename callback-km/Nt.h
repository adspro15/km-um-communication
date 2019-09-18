#pragma once
typedef struct _SYSTEM_THREAD_INFORMATION
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;
	KWAIT_REASON WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize;
	ULONG HardFaultCount;
	ULONG NumberOfThreadsHighWatermark;
	ULONGLONG CycleTime;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef struct _SYSTEM_GDI_DRIVER_INFORMATION
{
	UNICODE_STRING DriverName;
	PVOID ImageAddress;
	PVOID SectionPointer;
	PVOID EntryPoint;
	IMAGE_EXPORT_DIRECTORY *ExportSectionPointer;
	ULONG ImageLength;
}SYSTEM_GDI_DRIVER_INFORMATION,*PSYSTEM_GDI_DRIVER_INFORMATION;


typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE	Section;
	PVOID	MappedBase;
	PVOID	ImageBase;
	ULONG	ImageSize;
	ULONG	Flags;
	USHORT	LoadOrderIndex;
	USHORT	InitOrderIndex;
	USHORT	LoadCount;
	USHORT	OffsetToFileName;
	UCHAR	FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

struct _PEB {
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	BOOLEAN BitField;
	HANDLE Mutant;
	PVOID ImageBaseAddress;
};

#pragma pack(push, 1)
typedef struct __KTRAP_FRAME
{
	/* 0x0000 */ unsigned __int64 P1Home;
	/* 0x0008 */ unsigned __int64 P2Home;
	/* 0x0010 */ unsigned __int64 P3Home;
	/* 0x0018 */ unsigned __int64 P4Home;
	/* 0x0020 */ unsigned __int64 P5;
	/* 0x0028 */ char PreviousMode;
	/* 0x0029 */ unsigned char PreviousIrql;
	/* 0x002a */ unsigned char FaultIndicator;
	/* 0x002b */ unsigned char ExceptionActive;
	/* 0x002c */ unsigned long MxCsr;
	/* 0x0030 */ unsigned __int64 Rax;
	/* 0x0038 */ unsigned __int64 Rcx;
	/* 0x0040 */ unsigned __int64 Rdx;
	/* 0x0048 */ unsigned __int64 R8;
	/* 0x0050 */ unsigned __int64 R9;
	/* 0x0058 */ unsigned __int64 R10;
	/* 0x0060 */ unsigned __int64 R11;
	union
	{
		/* 0x0068 */ unsigned __int64 GsBase;
		/* 0x0068 */ unsigned __int64 GsSwap;
	}; /* size: 0x0008 */
	/* 0x0070 */ struct _M128A Xmm0;
	/* 0x0080 */ struct _M128A Xmm1;
	/* 0x0090 */ struct _M128A Xmm2;
	/* 0x00a0 */ struct _M128A Xmm3;
	/* 0x00b0 */ struct _M128A Xmm4;
	/* 0x00c0 */ struct _M128A Xmm5;
	union
	{
		/* 0x00d0 */ unsigned __int64 FaultAddress;
		/* 0x00d0 */ unsigned __int64 ContextRecord;
		/* 0x00d0 */ unsigned __int64 TimeStampCKCL;
	}; /* size: 0x0008 */
	/* 0x00d8 */ unsigned __int64 Dr0;
	/* 0x00e0 */ unsigned __int64 Dr1;
	/* 0x00e8 */ unsigned __int64 Dr2;
	/* 0x00f0 */ unsigned __int64 Dr3;
	/* 0x00f8 */ unsigned __int64 Dr6;
	/* 0x0100 */ unsigned __int64 Dr7;
	union
	{
		struct
		{
			/* 0x0108 */ unsigned __int64 DebugControl;
			/* 0x0110 */ unsigned __int64 LastBranchToRip;
			/* 0x0118 */ unsigned __int64 LastBranchFromRip;
			/* 0x0120 */ unsigned __int64 LastExceptionToRip;
			/* 0x0128 */ unsigned __int64 LastExceptionFromRip;
		}; /* size: 0x0028 */
		struct
		{
			/* 0x0108 */ unsigned __int64 LastBranchControl;
			/* 0x0110 */ unsigned long LastBranchMSR;
		}; /* size: 0x000c */
	}; /* size: 0x0028 */
	/* 0x0130 */ unsigned short SegDs;
	/* 0x0132 */ unsigned short SegEs;
	/* 0x0134 */ unsigned short SegFs;
	/* 0x0136 */ unsigned short SegGs;
	/* 0x0138 */ unsigned __int64 TrapFrame;
	/* 0x0140 */ unsigned __int64 Rbx;
	/* 0x0148 */ unsigned __int64 Rdi;
	/* 0x0150 */ unsigned __int64 Rsi;
	/* 0x0158 */ unsigned __int64 Rbp;
	union
	{
		/* 0x0160 */ unsigned __int64 ErrorCode;
		/* 0x0160 */ unsigned __int64 ExceptionFrame;
		/* 0x0160 */ unsigned __int64 TimeStampKlog;
	}; /* size: 0x0008 */
	/* 0x0168 */ unsigned __int64 Rip;
	/* 0x0170 */ unsigned short SegCs;
	/* 0x0172 */ unsigned char Fill0;
	/* 0x0173 */ unsigned char Logging;
	/* 0x0174 */ unsigned short Fill1[2];
	/* 0x0178 */ unsigned long EFlags;
	/* 0x017c */ unsigned long Fill2;
	/* 0x0180 */ unsigned __int64 Rsp;
	/* 0x0188 */ unsigned short SegSs;
	/* 0x018a */ unsigned short Fill3;
	/* 0x018c */ long CodePatchCycle;
} _KTRAP_FRAME, *_PKTRAP_FRAME; /* size: 0x0190 */
#pragma pack(pop)

typedef struct _KSTACK_CONTROL {

	DWORD64 StackBase;
	DWORD64 StackLimit;
	DWORD64 PreviousStackBase;
	DWORD64 PreviousStackLimit;
	DWORD64 Spare0;
	DWORD64 PreviousInitialStack;
}KSTACK_CONTROL,*PKSTACK_CONTROL;


DECLSPEC_ALIGN(8) typedef struct _DXGKWIN32K_INTERFACE {

	WORD	 Size;
	WORD	 Magic;
	DWORD64	 Null;
	PVOID	 pFn[0x1FE];

}DXGKWIN32K_INTERFACE, *PDXGKWIN32K_INTERFACE;

typedef NTSTATUS(NTAPI *GDI_BATCHFLUSH_ROUTINE) (VOID);

DECLSPEC_IMPORT
NTSTATUS
NTAPI
NtQuerySystemInformation(
	IN	DWORD					SystemInformationClass,
	OUT PVOID                   SystemInformation,
	IN	ULONG                   SystemInformationLength,
	OUT PULONG                  ReturnLength
);

DECLSPEC_IMPORT
NTSTATUS
NTAPI
NtSetSystemInformation(
	IN DWORD_PTR SystemInformationClass,
	IN PVOID SystemInformation,
	IN ULONG SystemInformationLength
);

DECLSPEC_IMPORT
PPEB
NTAPI
PsGetProcessPeb(
	IN PEPROCESS Process
);

DECLSPEC_IMPORT
PNT_TIB64
NTAPI
PsGetThreadTeb(
	IN PETHREAD Thread
);

DECLSPEC_IMPORT
NTSTATUS
NTAPI
MmCopyVirtualMemory(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
);

typedef NTSTATUS
(NTAPI*OpenAdapter_t)(
	PVOID
	);

typedef NTSTATUS
(NTAPI*KiCallUserMode_t)(
	PVOID *Outputbuffer,
	PULONG OutputLength,
	//Added in windows 8+
	PKSTACK_CONTROL KSC,
	DWORD64 NewStackBase
	);

typedef PVOID
(NTAPI*MmCreateKernelStack_t)(
	BOOLEAN LargeStack,
	WORD NodeNumber,
	PETHREAD Thread
	);

typedef VOID
(NTAPI*MmDeleteKernelStack_t)(
	PVOID Stack,
	BOOLEAN LargeStack
	);