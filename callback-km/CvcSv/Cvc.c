#include "../Native/Native.h"
#include "../hde/hde64.h"
#include "../../Declaration.h"
#include "Cvc.h"
#include "CvcInternal.h"

BOOLEAN CvcClosure = FALSE;
BOOLEAN Shutdown = FALSE;
KGUARDED_MUTEX CvcMutex;
PEPROCESS ClientProcess = NULL;
PVOID pfnDispatcher = NULL;
HANDLE CvcpPendingThreadId = NULL;


extern OpenAdapter_t pfOpenAdapter;

#pragma code_seg(push)
#pragma code_seg("PAGE")

NTSTATUS
CvcpOpenAdapterHook(
	PVOID Arg
);

NTSTATUS
CvcpProcessAddConnectionMsg(
	const pCvcAddConnection Message
) {

	PAGED_CODE();

	NTSTATUS Status = STATUS_SUCCESS;

	PETHREAD SlaveThread = NULL;
	PRKEVENT RequestEvent = NULL;
	PRKEVENT CompliteEvent = NULL;

	Status = ObReferenceObjectByHandleWithTag(
		Message->SlaveHandle,
		(ACCESS_MASK)2,
		*PsThreadType,
		UserMode,
		'tlfD',
		&SlaveThread,
		NULL
	);

	if (!NT_SUCCESS(Status)) {

		DbgPrint("%s: Cannot reference thread\n", __FUNCTION__);
		goto FinalStub;
	}

	Status = ObReferenceObjectByHandleWithTag(
		Message->RequestEvent,
		(ACCESS_MASK)2,
		*ExEventObjectType,
		UserMode,
		'tlfD',
		&RequestEvent,
		NULL
	);

	if (!NT_SUCCESS(Status)) {

		DbgPrint("%s: Cannot reference RequestEvent\n", __FUNCTION__);
		goto FinalStub;
	}

	Status = ObReferenceObjectByHandleWithTag(
		Message->CompliteEvent,
		(ACCESS_MASK)2,
		*ExEventObjectType,
		UserMode,
		'tlfD',
		&CompliteEvent,
		NULL
	);

	if (!NT_SUCCESS(Status)) {

		DbgPrint("%s: Cannot reference CompliteEvent\n", __FUNCTION__);
		goto FinalStub;
	}

	CvcpPendingThreadId = PsGetThreadId(SlaveThread);

	CvciHookOpenAdapter((PVOID)CvcpOpenAdapterHook);

	KeSetEvent(RequestEvent, 1, FALSE);

	LARGE_INTEGER Timeout = { .QuadPart = -8000 };

	int RetryCount = 0;

	while (KeWaitForSingleObject(
		CompliteEvent,
		Executive,
		KernelMode,
		TRUE,
		&Timeout) != STATUS_WAIT_0) {

		if (PsIsThreadTerminating(SlaveThread)) {

			DbgPrint("%s: PsIsThreadTerminating(SlaveThread)\n", __FUNCTION__);
			Status = STATUS_THREAD_IS_TERMINATING;
			break;
		}
		else if (RetryCount > 0x60) {

			DbgPrint("%s: RetryCount > 0x60\n", __FUNCTION__);
			Status = STATUS_DRIVER_CANCEL_TIMEOUT;
			break;
		}

		RetryCount++;
	}

FinalStub:;

	if (SlaveThread) {

		ObDereferenceObject(SlaveThread);
	}

	if (CompliteEvent) {

		ObDereferenceObject(CompliteEvent);
	}

	if (RequestEvent) {

		ObDereferenceObject(RequestEvent);
	}

	CvciUnhookOpenAdapter();

	CvcpPendingThreadId = NULL;

	return Status;
}

NTSTATUS
CvcpProcessHelloWorldMsg(
	const pCvcHelloWorld Message
) {

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	if (Message->Magic == ' cvC') {

		DbgPrint("Hello world!\n");

		ANSI_STRING UserOutput = RTL_CONSTANT_STRING("Hello, user!");

		PVOID Input = NULL;
		ULONG InputLen = 0;

		Status = CvciUsermodeCallout(
			CVCKE_DISPLAY,
			NULL,
			pfnDispatcher,
			UserOutput.Buffer,
			UserOutput.MaximumLength,
			&Input,
			&InputLen
		);
	}

	return Status;
}

NTSTATUS
CvcpProcessReadMsg(
	const pCvcRead Message
) {

	NTSTATUS Status = STATUS_SUCCESS;
	PEPROCESS Process = NULL;

	Status = PsLookupProcessByProcessId(Message->Pid, &Process);


	if (!NT_SUCCESS(Status)) {

		return Status;
	}

	SIZE_T Result = 0;

	__try {

		Status = MmCopyVirtualMemory(
			Process,
			(PVOID)Message->Ptr,
			PsGetCurrentProcess(),
			(PVOID)Message->pOut,
			Message->Size,
			KernelMode,
			&Result
		);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		Status = GetExceptionCode();
	}


	ObDereferenceObject(Process);

	return Status;
}

NTSTATUS
CvcpProcessWriteMsg(
	const pCvcWrite Message
) {

	NTSTATUS Status = STATUS_SUCCESS;
	PEPROCESS Process = NULL;

	Status = PsLookupProcessByProcessId(Message->Pid, &Process);

	if (!NT_SUCCESS(Status)) {

		return Status;
	}

	SIZE_T Result = 0;

	__try {

		Status = MmCopyVirtualMemory(
			PsGetCurrentProcess(),
			(PVOID)Message->pSrc,
			Process,
			(PVOID)Message->Ptr,
			Message->Size,
			KernelMode,
			&Result
		);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		Status = GetExceptionCode();
	}

	ObDereferenceObject(Process);

	return Status;
}

BOOLEAN
CvcpProcessUserMessage(
	const BOOLEAN IsMainConnection,
	const PVOID InputData,
	const ULONG InputDataLen
) {

	NTSTATUS UserStatus = STATUS_SUCCESS;
	pCvcCLMsg ClMessage = (pCvcCLMsg)ALIGN_UP_BY(
		alloca(InputDataLen + MEMORY_ALLOCATION_ALIGNMENT),
		MEMORY_ALLOCATION_ALIGNMENT
	);

	__try {

		RtlSecureZeroMemory(ClMessage, InputDataLen);
		RtlCopyMemory(ClMessage, InputData, InputDataLen);

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		ClMessage = NULL;
		UserStatus = GetExceptionCode();
	}

	if (!ClMessage || !NT_SUCCESS(UserStatus)) {

		DbgPrint("%s: Exception occured while trying to access user message\n", __FUNCTION__);
		return FALSE;
	}

	__try {

		*ClMessage->pResultStatus = STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		UserStatus = GetExceptionCode();
	}

	if (!NT_SUCCESS(UserStatus)) {

		DbgPrint("%s: Exception while trying to write ResultStatus\n", __FUNCTION__);
		return FALSE;
	}

	PRKEVENT CompliteEvent;
	UserStatus = ObReferenceObjectByHandleWithTag(
		ClMessage->CompliteEvent,
		(ACCESS_MASK)2,
		*ExEventObjectType,
		UserMode,
		'tlfD',
		&CompliteEvent,
		NULL
	);

	if (!NT_SUCCESS(UserStatus)) {

		DbgPrint("%s: Cannot reference event\n", __FUNCTION__);
		return FALSE;
	}

	switch (((pCvcNull)&ClMessage->Data)->Type)
	{
	case CVCCL_ADD_CONNECTION:
		UserStatus = IsMainConnection
			? CvcpProcessAddConnectionMsg((pCvcAddConnection)&ClMessage->Data)
			: STATUS_ILLEGAL_FUNCTION;
		break;
	case CVCCL_HELLO_WORLD:
		UserStatus = CvcpProcessHelloWorldMsg((pCvcHelloWorld)&ClMessage->Data);
		break;
	case CVCCL_READ:
		UserStatus = CvcpProcessReadMsg((pCvcRead)&ClMessage->Data);
		break;
	case CVCCL_WRITE:
		UserStatus = CvcpProcessWriteMsg((pCvcWrite)&ClMessage->Data);
		break;
	default:
		UserStatus = STATUS_INVALID_PARAMETER;
		break;
	}

	*ClMessage->pResultStatus = UserStatus;

	KeSetEvent(CompliteEvent, 1, FALSE);
	ObDereferenceObject(CompliteEvent);
	return TRUE;
}

VOID
CvcMain(
	PVOID StartContext
) {

	UNREFERENCED_PARAMETER(StartContext);
	PAGED_CODE();

	KeInitializeGuardedMutex(&CvcMutex);

	while (!CvcClosure) {

		PAGED_CODE();

		while (!NT_SUCCESS(CvcCreate())) {

			if (CvcClosure) {

				CvciExit();
				CvcTerminate();
				PsTerminateSystemThread(0);
			}

			LARGE_INTEGER WaitTime = { .QuadPart = -1000 };

			KeDelayExecutionThread(
				KernelMode,
				TRUE,
				&WaitTime
			);
		}

		KeWaitForSingleObject(
			ClientProcess,
			Executive,
			KernelMode,
			TRUE,
			NULL
		);

		CvcTerminate();
	}

	CvciExit();

	PsTerminateSystemThread(0);
}

BOOLEAN CvcpPrCmp(
	PEPROCESS TempPr,
	PSYSTEM_THREAD_INFORMATION ThreadsInfo,
	DWORD_PTR Limit
) {

	UNREFERENCED_PARAMETER(ThreadsInfo);
	UNREFERENCED_PARAMETER(Limit);
	PAGED_CODE();

	BOOLEAN Correct = FALSE;
	KAPC_STATE ApcState;
	KeStackAttachProcess(TempPr, &ApcState);

	__try {

		PPEB Peb = PsGetProcessPeb(TempPr);

		pfnDispatcher = LdrFindProcAdressA(Peb->ImageBaseAddress, "KeUserCallbackDispatcher");

		if (pfnDispatcher) {

			Correct = TRUE;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		DbgPrint("%s: Exception 0x%X\n", __FUNCTION__, GetExceptionCode());
	}

	if (!Correct) {

		pfnDispatcher = NULL;
	}

	KeUnstackDetachProcess(&ApcState);

	return Correct;
}

VOID
CvcpDispatcher(
	const pCvcConnection pConnection
) {

	const BOOLEAN IsMainConnection = pConnection == NULL;

	while (!Shutdown && !PsIsThreadTerminating(KeGetCurrentThread())) {

		PVOID Input = NULL;
		ULONG InputLen = 0;

		NTSTATUS Status = CvciUsermodeCallout(
			CVCKE_NOP,
			pConnection,
			pfnDispatcher,
			NULL,
			0,
			&Input,
			&InputLen
		);

		if (NT_SUCCESS(Status) && Input && InputLen) {

			if (!CvcpProcessUserMessage(IsMainConnection, Input, InputLen)) {

				/*
				Something hardly messed up - break connection
				*/
				DbgPrint("%s: Break connection\n", __FUNCTION__);
				return;
			}
		}
	}
}

NTSTATUS
CvcpOpenAdapterHook(
	PVOID Arg
) {

	KeAcquireGuardedMutex(&CvcMutex);

	if (IoGetCurrentProcess() == ClientProcess &&
		CvcpPendingThreadId
		? CvcpPendingThreadId == PsGetCurrentThreadId()
		: TRUE) {

		CvciUnhookOpenAdapter();
		KeReleaseGuardedMutex(&CvcMutex);

		NTSTATUS Status = STATUS_SUCCESS;

		ConnectionRequest Request = { .CompliteEvent = NULL, .Connection = NULL};
		
		__try {
		
			RtlCopyMemory(&Request, CvciGetUserArgument(), sizeof(ConnectionRequest));
		}
		__except(EXCEPTION_EXECUTE_HANDLER) {

			DbgPrint("%s: Exception read request\n", __FUNCTION__);
			Status = GetExceptionCode();
		}

		if (!NT_SUCCESS(Status)) {

			return STATUS_CONNECTION_ABORTED;
		}

		if (CvcpPendingThreadId && Request.Connection) {

			PRKEVENT CompliteEvent;

			Status = ObReferenceObjectByHandleWithTag(
				Request.CompliteEvent,
				(ACCESS_MASK)2,
				*ExEventObjectType,
				UserMode,
				'tlfD',
				&CompliteEvent,
				NULL
			);

			if (!NT_SUCCESS(Status)) {
				DbgPrint("%s: Failed referencing hCompliteEvent\n", __FUNCTION__);
				return STATUS_CONNECTION_ABORTED;
			}
			
			KeSetEvent(CompliteEvent, 1, FALSE);
			ObDereferenceObject(CompliteEvent);
			CvcpPendingThreadId = NULL;
		}
		else if (CvcpPendingThreadId || Request.Connection) {

			DbgPrint("%s: CvcpPendingThreadId || Request.Connection\n", __FUNCTION__);
			return STATUS_CONNECTION_ABORTED;
		}

		CvcpDispatcher(Request.Connection);

		return STATUS_CONNECTION_ABORTED;

	}

	KeReleaseGuardedMutex(&CvcMutex);

	return pfOpenAdapter(Arg);
}

NTSTATUS
CvcCreate(
	VOID
) {

	PAGED_CODE();
	Shutdown = FALSE;

	NTSTATUS Status = UtFindProcesses(L"CvcUm.exe", &ClientProcess, CvcpPrCmp);

	if (!NT_SUCCESS(Status)) {

		return Status;
	}

	KAPC_STATE Kapc;

	KeStackAttachProcess(ClientProcess, &Kapc);
	CvciHookOpenAdapter((PVOID)CvcpOpenAdapterHook);//patch dxgk interface for process session
	KeUnstackDetachProcess(&Kapc);

	return Status;
}

VOID
CvcTerminate(
	VOID
) {

	PAGED_CODE();
	Shutdown = TRUE;
	CvcpPendingThreadId = NULL;

	if (ClientProcess) {

		KAPC_STATE Kapc;

		KeStackAttachProcess(ClientProcess, &Kapc);
		CvciUnhookOpenAdapter();
		KeUnstackDetachProcess(&Kapc);

		ObDereferenceObject(ClientProcess);
		ClientProcess = NULL;
	}

	pfnDispatcher = NULL;
}
#pragma code_seg(pop)
