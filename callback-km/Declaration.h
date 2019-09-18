#pragma once
#include "../callback-um/CRT/Semaphore.h"

/*
Kernelmode message type that describe what subroutine should be run on usermode
*/
typedef enum _CvcMsgTypeKe
{
	CVCKE_NOP,
	CVCKE_DISPLAY,
	CVCKE_MAX,
	CVCKE_FORCE_DWORD = 0x7fffffff
}CvcMsgTypeKe, * pCvcMsgTypeKe;

/*
Usermode message type that describe what subroutine should be run on kernelmode
*/
typedef enum _CvcMsgTypeCL
{
	CVCCL_ADD_CONNECTION,
	CVCCL_HELLO_WORLD,
	CVCCL_READ,
	CVCCL_WRITE,
	CVCCL_MAX,
	CVCCL_FORCE_DWORD = 0x7fffffff
}CvcMsgTypeCL, * pCvcMsgTypeCL;

/*
User message that will be passed to kernelmode dispatcher
*/
typedef struct _CvcCLMsg {
	/*
	Pointer to variable that will recive operation status
	*/
	volatile NTSTATUS* pResultStatus;
	/*
	Event that used for synchronisation betwen kernelmode\usermode. Will be in signal state when request are complited
	*/
	HANDLE				CompliteEvent;
	/*
	Offset to user defined message
	*/
	CHAR				Data;
}CvcCLMsg, * pCvcCLMsg;

/*
Usermode structure that describe connection and being used for communication.
Created internally and should be acessed internally.
*/
typedef struct _CvcConnection {

	/*
	Thread id of master thread
	*/
	DWORD				MasterId;
	/*
	Thread id of slave thread
	*/
	DWORD				SlaveId;
	/*
	Handle to slave thread
	*/
	HANDLE				SlaveHandle;
	/*
	Double linked list that links connections
	*/
	LIST_ENTRY			CvcConnectionLinks;
	/*
	Handle to event that will be in signal state when request are exist
	*/
	HANDLE				RequestEvent;
	/*
	Semaphore that will be owned when callout in processing
	*/
	SEMAPHORE			CalloutSema;
	/*
	Status of last operation
	*/
	volatile NTSTATUS		LastStatus;
	/*
	Handle to event that will be in signal state when request are complited
	*/
	HANDLE				CompliteEvent;
	/*
	Lenght of pending message in bytes
	*/
	ULONG				PendingMsgLen;
	/*
	Pointer to pending message
	*/
	pCvcCLMsg			pMsgPending;

}CvcConnection, * pCvcConnection;

#ifndef CVCMESSAGE_COMMON
/***/#define CVCMESSAGE_COMMON sizeof(volatile NTSTATUS *) + sizeof(HANDLE)
#endif

typedef struct _ConnectionRequest {
	pCvcConnection 			Connection;
	HANDLE 				CompliteEvent;
}ConnectionRequest, * pConnectionRequest;

typedef struct _CvcNull {
	CvcMsgTypeCL			Type;
}CvcNull, * pCvcNull;

typedef struct _CvcAddConnection {
	CvcMsgTypeCL			Type;
	HANDLE				SlaveHandle;
	HANDLE				RequestEvent;
	HANDLE				CompliteEvent;
}CvcAddConnection, * pCvcAddConnection;

typedef struct _CvcHelloWorld {
	CvcMsgTypeCL			Type;
	DWORD				Magic;
}CvcHelloWorld, * pCvcHelloWorld;

typedef struct _CvcRead {
	CvcMsgTypeCL			Type;
	HANDLE				Pid;
	DWORD64				Ptr;
	ULONG				Size;
	PVOID				pOut;
}CvcRead, * pCvcRead;

typedef struct _CvcWrite {
	CvcMsgTypeCL			Type;
	HANDLE				Pid;
	DWORD64				Ptr;
	ULONG				Size;
	PVOID				pSrc;
}CvcWrite, * pCvcWrite;
