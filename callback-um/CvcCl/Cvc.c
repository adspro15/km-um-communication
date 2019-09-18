#include "../stdafx.h"
#include "Cvc.h"
#include "../Cse/Cse.h"

#pragma comment(linker, "/export:KeUserCallbackDispatcher")
#pragma comment( lib, "gdi32.lib" )
#pragma comment( lib, "ntdll.lib" )

DECLSPEC_IMPORT
NTSTATUS
NTAPI
NtCallbackReturn(
	IN PVOID                Result OPTIONAL,
	IN ULONG                ResultLength,
	IN NTSTATUS             Status
);

NTSTATUS
CvcpProcessConnect(
	PVOID Arg,
	pConnectionRequest Request
);

NTSTATUS
CvcpPostAddConnection(
	const pCvcConnection pConnectionToAdd
);

LIST_ENTRY		CvcpConnectionsList;
SEMAPHORE		CvcpConnectionWorkerSema;
pCvcConnection	CvcpUserMainConnection = NULL;

DWORD
CvcpConnectionStart(
	LPVOID Param
) {

	const pCvcConnection TargetConnection = (pCvcConnection)Param;

	if (TargetConnection != NULL) {

		WaitForSingleObject(TargetConnection->RequestEvent, INFINITE);
	}

	char buff[0x60];
	*(HDC*)buff = GetDC(NULL);

	pConnectionRequest pRequest = (pConnectionRequest)ALIGN_UP(
		alloca(sizeof(ConnectionRequest) + MEMORY_ALLOCATION_ALIGNMENT),
		MEMORY_ALLOCATION_ALIGNMENT
	);

	pRequest->Connection = TargetConnection;
	pRequest->CompliteEvent = TargetConnection ? TargetConnection->CompliteEvent : NULL;

	NTSTATUS Status = CvcpProcessConnect(
		buff,
		pRequest
	);

	ReleaseDC(NULL, *(HDC*)buff);

	return Status;
}

NTSTATUS CvcpDispatcher(
	const CvcMsgTypeKe Msg,
	const PVOID Data,
	const ULONG DataLen,
	const pCvcConnection pConnection
) {

	const pCvcConnection TargetConnection = pConnection == NULL
		? CvcpUserMainConnection
		: pConnection;

	if (Msg == CVCKE_DISPLAY) {

		char* Buffer = alloca(DataLen);
		sprintf(Buffer, Data);
		CseOutputA(Buffer);

		return NtCallbackReturn(NULL, 0, STATUS_SUCCESS);
	}

	WaitForSingleObject(TargetConnection->RequestEvent, INFINITE);

	if (!TargetConnection->pMsgPending) {

		return NtCallbackReturn(NULL, 0, STATUS_INVALID_MESSAGE);
	}

	return NtCallbackReturn(TargetConnection->pMsgPending, TargetConnection->PendingMsgLen, STATUS_SUCCESS);
}

NTSTATUS
CvcpCreateConnection(
	pCvcConnection* ppConnection
) {

	if (!ppConnection) {

		return STATUS_INVALID_PARAMETER;
	}

	const pCvcConnection pConnection = (pCvcConnection)malloc(sizeof(CvcConnection));

	if (!pConnection) {

		return STATUS_NO_MEMORY;
	}

	ZeroMemory(pConnection, sizeof(CvcConnection));

	pConnection->MasterId = GetCurrentThreadId();

	if (!(pConnection->RequestEvent = CreateEventA(NULL, FALSE, FALSE, NULL))) {

		goto FailStub;
	}

	if (!(pConnection->CompliteEvent = CreateEventA(NULL, FALSE, FALSE, NULL))) {

		goto FailStub;
	}

	const BOOLEAN SecondaryConnection = ppConnection != &CvcpUserMainConnection;

	pConnection->SlaveHandle = CreateThread(NULL, 0, CvcpConnectionStart, SecondaryConnection ? (LPVOID)pConnection : NULL, 0, &pConnection->SlaveId);

	if (!pConnection->SlaveHandle) {

		goto FailStub;
	}

	LockSemaphore(&CvcpConnectionWorkerSema);

	InsertTailList(&CvcpConnectionsList, &pConnection->CvcConnectionLinks);

	if (SecondaryConnection) {

		if (!CvcpUserMainConnection) {

			SetLastError(ERROR_CONNECTION_INVALID);
			UnlockSemaphore(&CvcpConnectionWorkerSema);

			goto FailStub;
		}

		if (!NT_SUCCESS(CvcpPostAddConnection(pConnection))) {

			SetLastError(ERROR_CONNECTION_ABORTED);
			UnlockSemaphore(&CvcpConnectionWorkerSema);
			goto FailStub;
		}
	}

	UnlockSemaphore(&CvcpConnectionWorkerSema);

	*ppConnection = pConnection;

	return STATUS_SUCCESS;

FailStub:;

	if (pConnection->RequestEvent) {

		CloseHandle(pConnection->RequestEvent);
	}

	if (pConnection->CompliteEvent) {

		CloseHandle(pConnection->CompliteEvent);
	}

	if (pConnection->SlaveHandle) {

		TerminateThread(pConnection->SlaveHandle, 0);
		CloseHandle(pConnection->SlaveHandle);
	}

	free(pConnection);

	return NTSTATUS_FROM_WIN32(GetLastError());
}

VOID
CvcpCloseConnection(
	const pCvcConnection pConnection
) {

	if (!pConnection) {

		return;
	}

	LockSemaphore(&CvcpConnectionWorkerSema);

	TerminateThread(pConnection->SlaveHandle, 0);
	CloseHandle(pConnection->SlaveHandle);
	CloseHandle(pConnection->RequestEvent);
	CloseHandle(pConnection->CompliteEvent);
	RemoveEntryList(&pConnection->CvcConnectionLinks);
	free(pConnection);

	UnlockSemaphore(&CvcpConnectionWorkerSema);
}

DWORD
CvcpThreadStart(
	LPVOID Param
) {

	NTSTATUS Status = STATUS_SUCCESS;
	pCvcConnection Connection = NULL;

	Status = CvcpCreateConnection(&Connection);

	if (!NT_SUCCESS(Status)) {

		return Status;
	}

	__try {

		__try {

			Status = ((CvcThreadStart_t)Param)(Connection);
		}
		__finally {

			CvcpCloseConnection(Connection);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		Status = GetExceptionCode();
	}

	return Status;
}

NTSTATUS
CvcCreate(
	VOID
) {

	if (CvcpUserMainConnection) {

		return STATUS_ALREADY_COMPLETE;
	}

	InitializeListHead(&CvcpConnectionsList);
	return CvcpCreateConnection(&CvcpUserMainConnection);
}

VOID
CvcTerminate(
	VOID
) {

	if (CvcpUserMainConnection) {

		CvcpCloseConnection(CvcpUserMainConnection);
		CvcpUserMainConnection = NULL;
	}
}

VOID
CvcWaitConnections(
	VOID
) {

	while (TRUE) {

		Sleep(0x1000);

		LockSemaphore(&CvcpConnectionWorkerSema);

		if (!CvcpUserMainConnection || CvcpConnectionsList.Blink == &CvcpUserMainConnection->CvcConnectionLinks) {

			UnlockSemaphore(&CvcpConnectionWorkerSema);
			break;
		}

		UnlockSemaphore(&CvcpConnectionWorkerSema);
	}
}

BOOLEAN
CvcConnectionActive(
	const pCvcConnection pConnection
) {

	const pCvcConnection TargetConnection = pConnection == NULL
		? CvcpUserMainConnection
		: pConnection;

	BOOLEAN ConnectionActive;

	LockSemaphore(&TargetConnection->CalloutSema);

	ConnectionActive = TargetConnection->LastStatus != STATUS_CONNECTION_DISCONNECTED;

	UnlockSemaphore(&TargetConnection->CalloutSema);

	return ConnectionActive;
}

NTSTATUS
CvcSpawnThread(
	const CvcThreadStart_t ThreadStart
) {

	HANDLE Master = CreateThread(NULL, 0, CvcpThreadStart, (LPVOID)ThreadStart, 0, NULL);

	if (!Master) {

		return NTSTATUS_FROM_WIN32(GetLastError());
	}

	CloseHandle(Master);

	return STATUS_SUCCESS;
}

NTSTATUS
CvcPostEx(
	const PVOID pData,
	const ULONG DataLen,
	const pCvcConnection pConnection
) {

	const pCvcConnection TargetConnection = pConnection == NULL
		? CvcpUserMainConnection
		: pConnection;

	if (!TargetConnection) {

		return STATUS_CONNECTION_INVALID;
	}

	LockSemaphore(&TargetConnection->CalloutSema);

	if (TargetConnection->LastStatus == STATUS_CONNECTION_DISCONNECTED) {

		UnlockSemaphore(&TargetConnection->CalloutSema);
		return STATUS_CONNECTION_DISCONNECTED;
	}

	const ULONG MessageSize =
		CVCMESSAGE_COMMON +
		DataLen;

	TargetConnection->PendingMsgLen = MessageSize;

	TargetConnection->pMsgPending = (pCvcCLMsg)ALIGN_UP(
		alloca(MessageSize + MEMORY_ALLOCATION_ALIGNMENT),
		MEMORY_ALLOCATION_ALIGNMENT
	);

	ZeroMemory(TargetConnection->pMsgPending, MessageSize);
	TargetConnection->pMsgPending->pResultStatus = &TargetConnection->LastStatus;
	TargetConnection->pMsgPending->CompliteEvent = TargetConnection->CompliteEvent;
	memcpy(&TargetConnection->pMsgPending->Data, pData, DataLen);

	SetEvent(TargetConnection->RequestEvent);

	DWORD ExitCode = 0;

	while (GetExitCodeThread(TargetConnection->SlaveHandle, &ExitCode) && ExitCode == STILL_ACTIVE) {

		if (WaitForSingleObject(TargetConnection->CompliteEvent, 0x1000) == WAIT_OBJECT_0) {

			break;
		}
	}

	NTSTATUS Status;

	if (ExitCode == STILL_ACTIVE) {

		Status = TargetConnection->LastStatus;
	}
	else {

		Status = TargetConnection->LastStatus = STATUS_CONNECTION_DISCONNECTED;
	}

	TargetConnection->pMsgPending = NULL;

	UnlockSemaphore(&TargetConnection->CalloutSema);

	return Status;
}

NTSTATUS
CvcpPostAddConnection(
	const pCvcConnection pConnectionToAdd
) {

	CvcAddConnection AddConnection;
	AddConnection.Type = CVCCL_ADD_CONNECTION;
	AddConnection.SlaveHandle = pConnectionToAdd->SlaveHandle;
	AddConnection.RequestEvent = pConnectionToAdd->RequestEvent;
	AddConnection.CompliteEvent = pConnectionToAdd->CompliteEvent;

	return CvcPostEx(&AddConnection, sizeof(AddConnection), NULL);
}

NTSTATUS
CvcPostHelloWorld(
	const pCvcConnection pCurrentConnection
) {

	CvcHelloWorld HelloWorld;
	HelloWorld.Type = CVCCL_HELLO_WORLD;
	HelloWorld.Magic = ' cvC';

	return CvcPostEx(&HelloWorld, sizeof(HelloWorld), pCurrentConnection);
}

NTSTATUS
CvcPostRead(
	const pCvcConnection pCurrentConnection,
	const HANDLE Pid,
	const DWORD64 Ptr,
	const ULONG Size,
	const PVOID pOut
) {

	CvcRead Read;
	Read.Type = CVCCL_READ;
	Read.Pid = Pid;
	Read.Ptr = Ptr;
	Read.Size = Size;
	Read.pOut = pOut;

	return CvcPostEx(&Read, sizeof(Read), pCurrentConnection);
}


NTSTATUS
CvcPostWrite(
	const pCvcConnection pCurrentConnection,
	const HANDLE Pid,
	const DWORD64 Ptr,
	const ULONG Size,
	const PVOID pSrc
) {

	CvcWrite Write;
	Write.Type = CVCCL_WRITE;
	Write.Pid = Pid;
	Write.Ptr = Ptr;
	Write.Size = Size;
	Write.pSrc = pSrc;

	return CvcPostEx(&Write, sizeof(Write), pCurrentConnection);
}
