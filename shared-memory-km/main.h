#pragma once
#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <Ntstrsafe.h>

const WCHAR SharedSectionName[] = L"\\BaseNamedObjects\\shared-memory";

PVOID	pSharedSection = NULL;
PVOID	pSectionObj = NULL;
HANDLE	hSection = NULL;

VOID DriverUnload(IN PDRIVER_OBJECT pDriverObject);
NTSTATUS CreateCall(PDEVICE_OBJECT DeviceObject, PIRP irp);
NTSTATUS CloseCall(PDEVICE_OBJECT DeviceObject, PIRP irp);

SECURITY_DESCRIPTOR SecDescriptor;
HANDLE sectionHandle;
PVOID	SharedSection = NULL;
PVOID	Sharedoutputvar = NULL;
ULONG DaclLength;
PACL Dacl;

HANDLE  SharedEventHandle_trigger = NULL;
PKEVENT SharedEvent_trigger = NULL;
UNICODE_STRING EventName_trigger;

HANDLE  SharedEventHandle_ReadyRead = NULL;
PKEVENT SharedEvent_ReadyRead = NULL;
UNICODE_STRING EventName_ReadyRead;

HANDLE  SharedEventHandle_dt = NULL;
PKEVENT SharedEvent_dt = NULL;
UNICODE_STRING EventName_dt;

extern NTKERNELAPI ERESOURCE PsLoadedModuleResource;
NTSTATUS ZwQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);
