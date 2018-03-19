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

	MmCopyVirtualMemory(SourceProcess, SourceAddress, TargetProcess, TargetAddress, Size, KernelMode, &Result);

	return STATUS_SUCCESS;
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
	NTSTATUS				status = STATUS_SUCCESS;
	ULONG					bytesIO = 0;
	PIO_STACK_LOCATION		stack;
	BOOLEAN					condition = FALSE;
	PMEMORY_READ_PARAM		memoryReadParam;
	PMEMORY_WRITE_PARAM		memoryWriteParam;
	PEPROCESS				process;

	UNREFERENCED_PARAMETER(DeviceObject);


	stack = IoGetCurrentIrpStackLocation(Irp);

	do {

		if (stack == NULL) {
			status = STATUS_INTERNAL_ERROR;
			break;
		}

		
		if (Irp->AssociatedIrp.SystemBuffer == NULL) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		switch (stack->Parameters.DeviceIoControl.IoControlCode) {
		case MEMORY_READ_REQUEST:
			//DbgPrint("[KMMM]MEMORY_READ_REQUEST");
			memoryReadParam = (PMEMORY_READ_PARAM)Irp->AssociatedIrp.SystemBuffer;

			if (stack->Parameters.DeviceIoControl.InputBufferLength != sizeof(MEMORY_READ_PARAM)) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}

			PsLookupProcessByProcessId((HANDLE)memoryReadParam->ProcessId, &process);
			KeReadProcessMemory(process, (PVOID)memoryReadParam->Address, memoryReadParam->Value, memoryReadParam->Size);
			
			status = STATUS_SUCCESS;
			bytesIO = sizeof(MEMORY_READ_PARAM);
			break;

		case MEMORY_WRITE_REQUEST:
			//DbgPrint("[KMMM]MEMORY_WRITE_REQUEST");
			memoryWriteParam = (PMEMORY_WRITE_PARAM)Irp->AssociatedIrp.SystemBuffer;

			if (stack->Parameters.DeviceIoControl.InputBufferLength != sizeof(MEMORY_WRITE_PARAM)) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}

			PsLookupProcessByProcessId((HANDLE)memoryWriteParam->ProcessId, &process);
			KeWriteProcessMemory(process, memoryWriteParam->Value, (PVOID)memoryWriteParam->Address, memoryWriteParam->Size);
			bytesIO = sizeof(MEMORY_WRITE_PARAM);
			break;

		default:
			status = STATUS_INVALID_PARAMETER;
		};

	} while (condition);

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = bytesIO;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS UnsupportedDispatch(
	_In_ struct _DEVICE_OBJECT *DeviceObject,
	_Inout_ struct _IRP *Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
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

	for (ULONG t = 0; t <= IRP_MJ_MAXIMUM_FUNCTION; t++)
	{
		DriverObject->MajorFunction[t] = &UnsupportedDispatch;
	}

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
