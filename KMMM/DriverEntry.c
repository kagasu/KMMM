#include <ntdef.h>
#include <ntifs.h>
#include <minwindef.h>
#include <stdlib.h>
#include "IoControlCodes.h"

#define DEVICE_NAME L"\\Device\\KMMM"
#define SYMBOLIC_LINK_NAME L"\\DosDevices\\KMMM"
#define DRIVER_NAME L"\\Driver\\KMMM"

NTKERNELAPI NTSTATUS IoCreateDriver(
	_In_		PUNICODE_STRING DriverName, OPTIONAL
	_In_		PDRIVER_INITIALIZE InitializationFunction
);

NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(
	_In_		HANDLE ProcessId,
	_Outptr_	PEPROCESS *Process
);

NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(
	_In_		PEPROCESS Process
);

PEPROCESS ClientProcess, TargetProcess;

NTSTATUS KeReadProcessMemory(PREAD_MEMORY_PARAM Param)
{
	KAPC_STATE KapcState;
	NTSTATUS NtStatus = STATUS_SUCCESS;
	PVOID DriverBuffer = ExAllocatePoolWithTag(NonPagedPool, Param->Size, 'sys');

	// read memory (target -> kernel)
	KeStackAttachProcess(TargetProcess, &KapcState);
	if (MmIsAddressValid((PVOID)Param->TargetBufferAddress))
	{
		RtlCopyMemory(DriverBuffer, (PVOID)Param->TargetBufferAddress, Param->Size);
	}
	KeUnstackDetachProcess(&KapcState);

	// transfer buffer (kernel -> client)
	KeStackAttachProcess(ClientProcess, &KapcState);
	if (MmIsAddressValid((PVOID)Param->ClientBufferAddress))
	{
		RtlCopyMemory((PVOID)Param->ClientBufferAddress, DriverBuffer, Param->Size);
	}
	KeUnstackDetachProcess(&KapcState);
	ExFreePool(DriverBuffer);
	return NtStatus;
}

NTSTATUS KeWriteProcessMemory(PWRITE_MEMORY_PARAM Param)
{
	KAPC_STATE KapcState;
	NTSTATUS NtStatus = STATUS_SUCCESS;
	PVOID DriverBuffer = ExAllocatePoolWithTag(NonPagedPool, Param->Size, 'sys');

	// read memory (client -> kernel)
	KeStackAttachProcess(ClientProcess, &KapcState);
	if (MmIsAddressValid((PVOID)Param->ClientBufferAddress))
	{
		RtlCopyMemory(DriverBuffer, (PVOID)Param->ClientBufferAddress, Param->Size);
	}
	KeUnstackDetachProcess(&KapcState);

	// transfer buffer (kernel -> target)
	KeStackAttachProcess(TargetProcess, &KapcState);
	if (MmIsAddressValid((PVOID)Param->TargetBufferAddress))
	{
		RtlCopyMemory((PVOID)Param->TargetBufferAddress, DriverBuffer, Param->Size);
	}
	KeUnstackDetachProcess(&KapcState);

	ExFreePool(DriverBuffer);
	return NtStatus;
}

NTSTATUS DevioctlDispatch(
	_In_	struct _DEVICE_OBJECT *DeviceObject,
	_Inout_	struct _IRP *Irp
)
{
	ULONG IoSize = 0;
	UNREFERENCED_PARAMETER(DeviceObject);
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

	if (stack->Parameters.DeviceIoControl.IoControlCode == INITIALIZE_DRIVER_REQUEST)
	{
		//DbgPrint("[KMMM]INITIALIZE_DRIVER_REQUEST");
		PINITIALIZE_DRIVER_PARAM InitializeDriverParam = (PINITIALIZE_DRIVER_PARAM)Irp->AssociatedIrp.SystemBuffer;
		PsLookupProcessByProcessId((HANDLE)InitializeDriverParam->ClientProcessId, &ClientProcess);
		PsLookupProcessByProcessId((HANDLE)InitializeDriverParam->TargetProcessId, &TargetProcess);
		InitializeDriverParam->TargetProcessBaseAddress = (DWORD64)PsGetProcessSectionBaseAddress(TargetProcess);
		IoSize = sizeof(INITIALIZE_DRIVER_PARAM);
	}
	else if(stack->Parameters.DeviceIoControl.IoControlCode == READ_MEMORY_REQUEST)
	{
		//DbgPrint("[KMMM]MEMORY_READ_REQUEST");
		PREAD_MEMORY_PARAM ReadMemoryParam = (PREAD_MEMORY_PARAM)Irp->AssociatedIrp.SystemBuffer;
		KeReadProcessMemory(ReadMemoryParam);
		IoSize = 0;
	}
	else if (stack->Parameters.DeviceIoControl.IoControlCode == WRITE_MEMORY_REQUEST)
	{
		//DbgPrint("[KMMM]MEMORY_WRITE_REQUEST");
		PWRITE_MEMORY_PARAM WriteMemoryParam = (PWRITE_MEMORY_PARAM)Irp->AssociatedIrp.SystemBuffer;
		KeWriteProcessMemory(WriteMemoryParam);
		IoSize = 0;
	};

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = IoSize;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS CreateDispatch(
	_In_ struct _DEVICE_OBJECT *DeviceObject,
	_Inout_ struct _IRP *Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

NTSTATUS CloseDispatch(
	_In_ struct _DEVICE_OBJECT *DeviceObject,
	_Inout_ struct _IRP *Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

NTSTATUS DriverInitialize(
	_In_  struct _DRIVER_OBJECT *DriverObject,
	_In_  PUNICODE_STRING RegistryPath
)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	UNICODE_STRING  SymLink, DevName;
	PDEVICE_OBJECT  devobj;

	RtlInitUnicodeString(&DevName, DEVICE_NAME);
	RtlInitUnicodeString(&SymLink, SYMBOLIC_LINK_NAME);

	IoCreateDevice(DriverObject, 0, &DevName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, TRUE, &devobj);
	IoCreateSymbolicLink(&SymLink, &DevName);
	
	devobj->Flags |= DO_BUFFERED_IO;

	DriverObject->MajorFunction[IRP_MJ_CREATE] = &CreateDispatch;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = &CloseDispatch;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &DevioctlDispatch;
	DriverObject->DriverUnload = NULL;

	devobj->Flags &= ~DO_DEVICE_INITIALIZING;

	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(
	_In_  struct _DRIVER_OBJECT *DriverObject,
	_In_  PUNICODE_STRING RegistryPath
)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	UNICODE_STRING  drvName;

	RtlInitUnicodeString(&drvName, DRIVER_NAME);
	IoCreateDriver(&drvName, &DriverInitialize);

	return STATUS_SUCCESS;
}
