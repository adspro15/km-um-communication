#pragma once
#include "../Declaration.h"
/*
Cvc - Communication via callback function prefix
*/

typedef NTSTATUS
(__fastcall* CvcThreadStart_t)
(const pCvcConnection pConnection);

NTSTATUS
CvcCreate(
	VOID
);

VOID
CvcTerminate(
	VOID
);

VOID
CvcWaitConnections(
	VOID
);

BOOLEAN
CvcConnectionActive(
	const pCvcConnection Connection
);

NTSTATUS
CvcSpawnThread(
	const CvcThreadStart_t ThreadStart
);

NTSTATUS
CvcPostEx(
	const PVOID pData,
	const ULONG DataLen,
	const pCvcConnection pConnection
);

NTSTATUS
CvcPostHelloWorld(
	const pCvcConnection CurrentConnection
);

NTSTATUS
CvcPostRead(
	const pCvcConnection pCurrentConnection,
	const HANDLE Pid,
	const DWORD64 Ptr,
	const ULONG Size,
	const PVOID pOut
);

NTSTATUS
CvcPostWrite(
	const pCvcConnection pCurrentConnection,
	const HANDLE Pid,
	const DWORD64 Ptr,
	const ULONG Size,
	const PVOID pSrc
);
