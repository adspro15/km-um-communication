#include <ntddk.h> 

const WCHAR sc_wszDeviceNameBuffer[]	= L"\\Device\\Dispatch_Test";
const WCHAR sc_wszDeviceSymLinkBuffer[] = L"\\DosDevices\\Dispatch_Test";

NTSTATUS OnIRPRead(PDEVICE_OBJECT pDriverObject, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDriverObject);

	char szBuffer[255] = "Hello from kernel land!";
	strcpy(pIrp->AssociatedIrp.SystemBuffer, szBuffer);
	DbgPrint("Message: %s(%u) sent from kernel!", szBuffer, strlen(szBuffer));

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = strlen(szBuffer);
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS OnIRPWrite(PDEVICE_OBJECT pDriverObject, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDriverObject);

	char szBuffer[255] = { 0 };
	strcpy(szBuffer, pIrp->AssociatedIrp.SystemBuffer);
	DbgPrint("User message received: %s(%u)", szBuffer, strlen(szBuffer));

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = strlen(szBuffer);
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS OnMajorFunctionCall(PDEVICE_OBJECT pDriverObject, PIRP pIrp)
{
	PIO_STACK_LOCATION pStack = IoGetCurrentIrpStackLocation(pIrp);
	switch (pStack->MajorFunction)
	{
		case IRP_MJ_READ:
			OnIRPRead(pDriverObject, pIrp);
			break;

		case IRP_MJ_WRITE:
			OnIRPWrite(pDriverObject, pIrp);
			break;

		default:
			pIrp->IoStatus.Status = STATUS_SUCCESS;
			IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	}
	return STATUS_SUCCESS;
}


VOID OnDriverUnload(IN PDRIVER_OBJECT pDriverObject)
{
	UNREFERENCED_PARAMETER(pDriverObject);

	DbgPrint("Driver unload routine triggered!\n");

	UNICODE_STRING symLink;
	RtlInitUnicodeString(&symLink, sc_wszDeviceSymLinkBuffer);

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
		DbgPrint("DispatchTestSys driver entry is null!\n");
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
	RtlInitUnicodeString(&deviceNameUnicodeString, sc_wszDeviceNameBuffer);
	RtlInitUnicodeString(&deviceSymLinkUnicodeString, sc_wszDeviceSymLinkBuffer);

	// Create the device.
	PDEVICE_OBJECT pDeviceObject = NULL;
	ntStatus = IoCreateDevice(pDriverObject, 0, &deviceNameUnicodeString, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
	if (ntStatus != STATUS_SUCCESS)
	{
		DbgPrint("DispatchTestSys IoCreateDevice fail! Status: %p\n", ntStatus);
		return ntStatus;
	}

	// Create the symbolic link
	ntStatus = IoCreateSymbolicLink(&deviceSymLinkUnicodeString, &deviceNameUnicodeString);
	if (ntStatus != STATUS_SUCCESS)
	{
		DbgPrint("DispatchTestSys IoCreateSymbolicLink fail! Status: %p\n", ntStatus);
		return ntStatus;
	}

	// Register driver major callbacks
	for (ULONG t = 0; t <= IRP_MJ_MAXIMUM_FUNCTION; t++)
		pDriverObject->MajorFunction[t] = &OnMajorFunctionCall;

	pDeviceObject->Flags |= DO_BUFFERED_IO;

	DbgPrint("Ioctl driver entry completed!\n");

	return STATUS_SUCCESS;
}


