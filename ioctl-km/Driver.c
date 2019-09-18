#include <ntifs.h> 
#include <ntddk.h> 
#include <ntstrsafe.h> 
#include <stdlib.h>

#define IOCTL_READ_MEM CTL_CODE(FILE_DEVICE_UNKNOWN, 0x999, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_WRITE_MEM CTL_CODE(FILE_DEVICE_UNKNOWN, 0x998, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)

PDEVICE_OBJECT pDeviceObject;
UNICODE_STRING dev, dos;

DRIVER_DISPATCH Create;
DRIVER_DISPATCH IOCTL;
DRIVER_DISPATCH Close;
DRIVER_UNLOAD Unload;

void Unload(PDRIVER_OBJECT pDriverObject) {
	IoDeleteSymbolicLink(&dos);
	IoDeleteDevice(pDriverObject->DeviceObject);
}

NTSTATUS Create(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS Close(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "kernel mod unloading");
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

struct {
	int PID;
	void * Addr;
	void * Value;
	int Bytes;
}
UserLand;

NTSTATUS NTAPI MmCopyVirtualMemory
(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
);

NTSTATUS ReadProcessMemory(HANDLE PID, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size) {
	SIZE_T Result;
	PEPROCESS SourceProcess, TargetProcess;
	PsLookupProcessByProcessId(PID, &SourceProcess);
	TargetProcess = PsGetCurrentProcess();
	__try {
		MmCopyVirtualMemory(SourceProcess, SourceAddress, TargetProcess, TargetAddress, Size, KernelMode, &Result);
		return STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return STATUS_ACCESS_DENIED;
	}
}

NTSTATUS WriteProcessMemory(HANDLE PID, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size) {
	SIZE_T Result;
	PEPROCESS SourceProcess, TargetProcess;
	PsLookupProcessByProcessId(PID, &SourceProcess);
	TargetProcess = PsGetCurrentProcess();
	__try {
		MmCopyVirtualMemory(TargetProcess, TargetAddress, SourceProcess, SourceAddress, Size, KernelMode, &Result);
		return STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return STATUS_ACCESS_DENIED;
	}
}

NTSTATUS IOCTL(PDEVICE_OBJECT DeviceObject, PIRP irp) {
	PUCHAR UserBuffer;
	PIO_STACK_LOCATION io;

	io = IoGetCurrentIrpStackLocation(irp);
	switch (io->Parameters.DeviceIoControl.IoControlCode) {
	case IOCTL_READ_MEM:
		memcpy(&UserLand, irp->AssociatedIrp.SystemBuffer, sizeof(UserLand));
		UserBuffer = (PUCHAR)MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
		if (UserBuffer && UserLand.Addr != NULL) {
			ReadProcessMemory((HANDLE)UserLand.PID, UserLand.Addr, (PVOID)UserBuffer, UserLand.Bytes);
		}
		KeFlushIoBuffers(irp->MdlAddress, TRUE, FALSE);
		irp->IoStatus.Information = 0;
		break;
	case IOCTL_WRITE_MEM:
		memcpy(&UserLand, irp->AssociatedIrp.SystemBuffer, sizeof(UserLand));
		UserBuffer = (PUCHAR)MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
		if (UserBuffer && UserLand.Addr != NULL) {
			WriteProcessMemory((HANDLE)UserLand.PID, UserLand.Addr, (PVOID)UserBuffer, UserLand.Bytes);
		}
		KeFlushIoBuffers(irp->MdlAddress, TRUE, FALSE);
		irp->IoStatus.Information = 0;
		break;
	default:

		irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		irp->IoStatus.Information = 0;

		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_INVALID_DEVICE_REQUEST;
	}
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\KRPM_Driver"), SymbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\KRPM_Driver");
PDEVICE_OBJECT pDeviceObject;

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath) {


	ULONG i;

	IoCreateDevice(pDriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
	IoCreateSymbolicLink(&SymbolicLink, &DeviceName);

	IoSetDeviceInterfaceState(pRegistryPath, TRUE);

	pDriverObject->MajorFunction[IRP_MJ_CREATE] = Create;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IOCTL;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = Close;

	pDriverObject->DriverUnload = Unload;

	pDeviceObject->Flags |= DO_DIRECT_IO;
	pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "kernel mod loaded");
	return STATUS_SUCCESS;
}