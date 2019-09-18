#pragma once
#include <windows.h>

typedef struct _KM_READ_REQUEST
{
	ULONG ProcessId;
	UINT_PTR SourceAddress;
	ULONGLONG Size;
	void* Output;

} KM_READ_REQUEST;

typedef struct _KM_WRITE_REQUEST
{
	ULONG ProcessId;
	ULONG ProcessidOfSource;
	UINT_PTR SourceAddress;
	UINT_PTR TargetAddress;
	ULONGLONG Size;
} KM_WRITE_REQUEST;

typedef struct _GET_USERMODULE_IN_PROCESS
{
	ULONG pid;
	ULONG64 BaseAddress;
} GET_USERMODULE_IN_PROCESS;
