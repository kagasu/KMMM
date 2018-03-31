#include <ntddk.h>
#include <minwindef.h>
#include <stdlib.h>
#include "IoControlCodes.h"

#define DEVICE_NAME L"\\Device\\KMMM"
#define SYMBOLIC_LINK_NAME L"\\DosDevices\\KMMM"
#define DRIVER_NAME L"\\Driver\\KMMM"

NTKERNELAPI NTSTATUS IoCreateDriver(
	IN PUNICODE_STRING DriverName, OPTIONAL
	IN PDRIVER_INITIALIZE InitializationFunction
);

NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(
	_In_ HANDLE ProcessId,
	_Outptr_ PEPROCESS *Process
);

NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(
	__in PEPROCESS Process
);

NTSTATUS NTAPI MmCopyVirtualMemory(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
);

NTSTATUS KeReadProcessMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	PEPROCESS SourceProcess = Process;
	PEPROCESS TargetProcess = PsGetCurrentProcess();
	SIZE_T Result;

	return NT_SUCCESS(MmCopyVirtualMemory(SourceProcess, SourceAddress, TargetProcess, TargetAddress, Size, KernelMode, &Result));
}

NTSTATUS KeWriteProcessMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	PEPROCESS SourceProcess = PsGetCurrentProcess();
	PEPROCESS TargetProcess = Process;
	SIZE_T Result;

	return NT_SUCCESS(MmCopyVirtualMemory(SourceProcess, SourceAddress, TargetProcess, TargetAddress, Size, KernelMode, &Result));
}

NTSTATUS DevioctlDispatch(
	_In_ struct _DEVICE_OBJECT *DeviceObject,
	_Inout_ struct _IRP *Irp
)
{
	ULONG bytesIO = 0;
	PEPROCESS process;

	UNREFERENCED_PARAMETER(DeviceObject);
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

	if (stack->Parameters.DeviceIoControl.IoControlCode == GET_PROCESS_BASE_ADDRESS_REQUEST)
	{
		//DbgPrint("[KMMM]GET_PROCESS_BASE_ADDRESS_PARAM");
		PGET_PROCESS_BASE_ADDRESS_PARAM getProcessBaseAddressParam = (PGET_PROCESS_BASE_ADDRESS_PARAM)Irp->AssociatedIrp.SystemBuffer;
		PsLookupProcessByProcessId((HANDLE)getProcessBaseAddressParam->ProcessId, &process);
		getProcessBaseAddressParam->BaseAddress = (DWORD64)PsGetProcessSectionBaseAddress(process);
		bytesIO = sizeof(GET_PROCESS_BASE_ADDRESS_PARAM);
	}
	else if(stack->Parameters.DeviceIoControl.IoControlCode == MEMORY_READ_REQUEST)
	{
		//DbgPrint("[KMMM]MEMORY_READ_REQUEST");
		PMEMORY_READ_PARAM memoryReadParam = (PMEMORY_READ_PARAM)Irp->AssociatedIrp.SystemBuffer;
		PsLookupProcessByProcessId((HANDLE)memoryReadParam->ProcessId, &process);
		KeReadProcessMemory(process, (PVOID)memoryReadParam->Address, memoryReadParam->Value, memoryReadParam->Size);
		bytesIO = sizeof(MEMORY_READ_PARAM);
	}
	else if (stack->Parameters.DeviceIoControl.IoControlCode == MEMORY_WRITE_REQUEST)
	{
		//DbgPrint("[KMMM]MEMORY_WRITE_REQUEST");
		PMEMORY_WRITE_PARAM memoryWriteParam = (PMEMORY_WRITE_PARAM)Irp->AssociatedIrp.SystemBuffer;
		PsLookupProcessByProcessId((HANDLE)memoryWriteParam->ProcessId, &process);
		KeWriteProcessMemory(process, memoryWriteParam->Value, (PVOID)memoryWriteParam->Address, memoryWriteParam->Size);
		bytesIO = 0;
	};

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = bytesIO;
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
