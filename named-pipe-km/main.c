#include <ntddk.h> 
#include <stdio.h>
#include <stdarg.h>

#define PIPE_OPEN_IO_CODE	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)  
#define PIPE_MSG_IO_CODE	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_NEITHER, FILE_ANY_ACCESS)  

const WCHAR gc_wszDeviceNameBuffer[]	= L"\\Device\\PipeClient_Test";
const WCHAR gc_wszDeviceSymLinkBuffer[] = L"\\DosDevices\\PipeClient_Test";
const WCHAR gc_wszPipeName[]			= L"\\Device\\NamedPipe\\TestCommPipe";

static HANDLE s_hServerPipe = NULL;
static KMUTEX s_pPipeMutex	= { 0 };

typedef struct _KERNEL_IO_DBG_MSG_DATA
{
	CHAR szMessage[255];
} SKernelIODbgMsgData, *PKernelIODbgMsgData;

// PIPE
VOID WritePipeMessage(const char* c_szMessage, ...)
{
	char szBuff[0x100];

	va_list vaArgList;
	va_start(vaArgList, c_szMessage);
	vsprintf(szBuff, c_szMessage, vaArgList);
	va_end(vaArgList);

	if (KeGetCurrentIrql() == PASSIVE_LEVEL)
	{
		KeWaitForMutexObject(&s_pPipeMutex, Executive, KernelMode, FALSE, NULL);

		if (s_hServerPipe)
		{
			IO_STATUS_BLOCK IoStatusBlock;
			ZwWriteFile(s_hServerPipe, 0, NULL, NULL, &IoStatusBlock, szBuff, (ULONG)strlen(szBuff) + 1, NULL, NULL);
		}

		KeReleaseMutex(&s_pPipeMutex, FALSE);
	} 
}

VOID OpenServerPipe()
{
	UNICODE_STRING usPipeName;
	RtlInitUnicodeString(&usPipeName, gc_wszPipeName);

	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes, &usPipeName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	KeWaitForMutexObject(&s_pPipeMutex, Executive, KernelMode, FALSE, NULL);

	IO_STATUS_BLOCK IoStatusBlock;
	NTSTATUS ntStatus = ZwCreateFile(&s_hServerPipe, FILE_WRITE_DATA | SYNCHRONIZE, &ObjectAttributes, &IoStatusBlock,0, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("ZwCreateFile fail, Status: %p\n", ntStatus);
	}

	KeReleaseMutex(&s_pPipeMutex, FALSE);
}

VOID CloseServerPipe()
{
	KeWaitForMutexObject(&s_pPipeMutex, Executive, KernelMode, FALSE, NULL);

	if (s_hServerPipe)
	{
		ZwClose(s_hServerPipe);
		s_hServerPipe = NULL;
	}

	KeReleaseMutex(&s_pPipeMutex, FALSE);
}

// IOCTL
#define IO_INPUT(Type)  ((Type)(pIrpStack->Parameters.DeviceIoControl.Type3InputBuffer)) 
#define IO_OUTPUT(Type) ((Type)(pIrp->UserBuffer))

NTSTATUS OnIoControl(PDEVICE_OBJECT pDriverObject, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDriverObject);

	DbgPrint("IRP_MJ_DEVICE_CONTROL handled!\n");

	NTSTATUS ntStatus = STATUS_SUCCESS;
	__try
	{
		PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
		ULONG uIoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
		switch (uIoControlCode)
		{
			case PIPE_OPEN_IO_CODE:
			{
				DbgPrint("Pipe open packet received\n");
				OpenServerPipe();
			} break;

			case PIPE_MSG_IO_CODE:
			{
				DbgPrint("Pipe message packet received\n");
				WritePipeMessage(IO_INPUT(PKernelIODbgMsgData)->szMessage);
			} break;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		ntStatus = STATUS_UNSUCCESSFUL;
		DbgPrint("OnIoControl Exception catched!\n");
	}

	pIrp->IoStatus.Status = ntStatus;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return ntStatus;
}

NTSTATUS OnMajorFunctionCall(PDEVICE_OBJECT pDriverObject, PIRP pIrp)
{
	PIO_STACK_LOCATION pStack = IoGetCurrentIrpStackLocation(pIrp);
	switch (pStack->MajorFunction)
	{
		case IRP_MJ_DEVICE_CONTROL:
			OnIoControl(pDriverObject, pIrp);
			break;

		default:
			pIrp->IoStatus.Status = STATUS_SUCCESS;
			IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	}
	return STATUS_SUCCESS;
}

// Routine
VOID OnDriverUnload(IN PDRIVER_OBJECT pDriverObject)
{
	UNREFERENCED_PARAMETER(pDriverObject);

	DbgPrint("Driver unload routine triggered!\n");

	CloseServerPipe();

	UNICODE_STRING symLink;
	RtlInitUnicodeString(&symLink, gc_wszDeviceSymLinkBuffer);

	IoDeleteSymbolicLink(&symLink);
	if (pDriverObject && pDriverObject->DeviceObject)
	{
		IoDeleteDevice(pDriverObject->DeviceObject);
	}
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryPath)
{
	// Process params
	UNREFERENCED_PARAMETER(pRegistryPath);

	if (!pDriverObject)
	{
		DbgPrint("NamedPipeTestSys driver entry is null!\n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	// Hello world!
	DbgPrint("Driver loaded, system range start in %p, Our entry at: %p\n", MmSystemRangeStart, DriverEntry);

	// Register unload routine
	pDriverObject->DriverUnload = &OnDriverUnload;

	// Veriable decleration
	NTSTATUS ntStatus = 0;

	// Normalize name and symbolic link.
	UNICODE_STRING deviceNameUnicodeString, deviceSymLinkUnicodeString;
	RtlInitUnicodeString(&deviceNameUnicodeString, gc_wszDeviceNameBuffer);
	RtlInitUnicodeString(&deviceSymLinkUnicodeString, gc_wszDeviceSymLinkBuffer);

	// Create the device.
	PDEVICE_OBJECT pDeviceObject = NULL;
	ntStatus = IoCreateDevice(pDriverObject, 0, &deviceNameUnicodeString, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
	if (ntStatus != STATUS_SUCCESS)
	{
		DbgPrint("NamedPipeTestSys IoCreateDevice fail! Status: %p\n", ntStatus);
		return ntStatus;
	}

	// Create the symbolic link
	ntStatus = IoCreateSymbolicLink(&deviceSymLinkUnicodeString, &deviceNameUnicodeString);
	if (ntStatus != STATUS_SUCCESS)
	{
		DbgPrint("NamedPipeTestSys IoCreateSymbolicLink fail! Status: %p\n", ntStatus);
		return ntStatus;
	}

	// Register driver major callbacks
	for (ULONG t = 0; t <= IRP_MJ_MAXIMUM_FUNCTION; t++)
		pDriverObject->MajorFunction[t] = &OnMajorFunctionCall;

	pDeviceObject->Flags |= DO_DIRECT_IO;
	pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	KeInitializeMutex(&s_pPipeMutex, 0);

	DbgPrint("NamedPipeTestSys driver entry completed!\n");

	return STATUS_SUCCESS;
}


