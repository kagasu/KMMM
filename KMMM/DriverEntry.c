#include <ntdef.h>
#include <ntifs.h>
#include <minwindef.h>
#include <stdlib.h>
#include "IoControlCodes.h"

#define DEVICE_NAME L"\\Device\\KMMM"
#define SYMBOLIC_LINK_NAME L"\\DosDevices\\KMMM"

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

UNICODE_STRING  SymLink;
PEPROCESS ClientProcess, TargetProcess;

NTSTATUS KeReadProcessMemory(PREAD_MEMORY_PARAM Param)
{
	KAPC_STATE KapcState;
	NTSTATUS NtStatus = STATUS_SUCCESS;
	PVOID DriverBuffer = ExAllocatePoolWithTag(NonPagedPool, Param->Size, 'sys');

	__try
	{
		// read memory (target -> kernel)
		KeStackAttachProcess(TargetProcess, &KapcState);
		ProbeForRead((CONST PVOID)Param->TargetBufferAddress, Param->Size, sizeof(CHAR));
		RtlCopyMemory(DriverBuffer, (PVOID)Param->TargetBufferAddress, Param->Size);
		KeUnstackDetachProcess(&KapcState);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KeUnstackDetachProcess(&KapcState);
		NtStatus = STATUS_ABANDONED;
	}
	__try
	{
		// transfer buffer (kernel -> client)
		KeStackAttachProcess(ClientProcess, &KapcState);
		ProbeForRead((CONST PVOID)Param->ClientBufferAddress, Param->Size, sizeof(CHAR));
		RtlCopyMemory((PVOID)Param->ClientBufferAddress, DriverBuffer, Param->Size);
		KeUnstackDetachProcess(&KapcState);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KeUnstackDetachProcess(&KapcState);
		NtStatus = STATUS_ABANDONED;
	}

	ExFreePool(DriverBuffer);
	return NtStatus;
}

NTSTATUS KeWriteProcessMemory(PWRITE_MEMORY_PARAM Param)
{
	KAPC_STATE KapcState;
	NTSTATUS NtStatus = STATUS_SUCCESS;
	PVOID DriverBuffer = ExAllocatePoolWithTag(NonPagedPool, Param->Size, 'sys');

	__try
	{
		// read memory (client -> kernel)
		KeStackAttachProcess(ClientProcess, &KapcState);
		ProbeForRead((CONST PVOID)Param->ClientBufferAddress, Param->Size, sizeof(CHAR));
		RtlCopyMemory(DriverBuffer, (PVOID)Param->ClientBufferAddress, Param->Size);
		KeUnstackDetachProcess(&KapcState);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KeUnstackDetachProcess(&KapcState);
		NtStatus = STATUS_ABANDONED;
	}
	__try
	{
		// transfer buffer (kernel -> target)
		KeStackAttachProcess(TargetProcess, &KapcState);
		ProbeForRead((CONST PVOID)Param->TargetBufferAddress, Param->Size, sizeof(CHAR));
		RtlCopyMemory((PVOID)Param->TargetBufferAddress, DriverBuffer, Param->Size);
		KeUnstackDetachProcess(&KapcState);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KeUnstackDetachProcess(&KapcState);
		NtStatus = STATUS_ABANDONED;
	}

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
	else if (stack->Parameters.DeviceIoControl.IoControlCode == READ_MEMORY_REQUEST)
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

NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject)
{
	UNREFERENCED_PARAMETER(pDriverObject);
	//DbgPrint("[KMMM]UnloadDriver");
	IoDeleteSymbolicLink(&SymLink);

	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(
	_In_  struct _DRIVER_OBJECT *DriverObject,
	_In_  PUNICODE_STRING RegistryPath
)
{
	//DbgPrint("[KMMM]DriverEntry");
	UNREFERENCED_PARAMETER(RegistryPath);

	UNICODE_STRING DevName;
	PDEVICE_OBJECT  DevObj;

	RtlInitUnicodeString(&DevName, DEVICE_NAME);
	RtlInitUnicodeString(&SymLink, SYMBOLIC_LINK_NAME);

	IoCreateDevice(DriverObject, 0, &DevName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, TRUE, &DevObj);
	IoCreateSymbolicLink(&SymLink, &DevName);

	DriverObject->MajorFunction[IRP_MJ_CREATE] = &CreateDispatch;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = &CloseDispatch;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &DevioctlDispatch;
	DriverObject->DriverUnload = UnloadDriver;

	return STATUS_SUCCESS;
}