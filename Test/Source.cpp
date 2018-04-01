#include <Windows.h>
#include <cstdio>
#include "IoControlCodes.h"

DWORD64 x = 100;

void Thread()
{
	while (1)
	{
		std::printf("%lld = 0x%p\n", x, &x);
		Sleep(1000);
	}
}

int main()
{
	CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)&Thread, NULL, NULL, NULL);
	Sleep(1000);

	HANDLE h = CreateFile(TEXT("\\\\.\\KMMM"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (h != INVALID_HANDLE_VALUE)
	{
		DWORD IoSize;

		// Initialize Driver
		INITIALIZE_DRIVER_PARAM initializeDriverParam;
		initializeDriverParam.ClientProcessId = GetCurrentProcessId();
		initializeDriverParam.TargetProcessId = GetCurrentProcessId();

		DeviceIoControl(
			h,
			INITIALIZE_DRIVER_REQUEST,
			&initializeDriverParam,
			sizeof(initializeDriverParam),
			&initializeDriverParam,
			sizeof(initializeDriverParam),
			&IoSize,
			NULL);
		std::printf("INITIALIZE_DRIVER_REQUEST\n");

		auto baseAddress = initializeDriverParam.TargetProcessBaseAddress;
		std::printf("base address = %llX\n", baseAddress);

		DWORD64 value = 0;

		// Read Memory
		READ_MEMORY_PARAM readMemoryParam;
		readMemoryParam.ClientBufferAddress = (DWORD64)&value;
		readMemoryParam.TargetBufferAddress = (DWORD64)&x;
		readMemoryParam.Size = sizeof(value);

		DeviceIoControl(
			h,
			READ_MEMORY_REQUEST,
			&readMemoryParam,
			sizeof(readMemoryParam),
			nullptr,
			0,
			&IoSize,
			NULL);
		std::printf("READ_MEMORY_REQUEST\n");
		std::printf("value %lld\n", value);

		// Write Memory
		value = 99999999999;
		WRITE_MEMORY_PARAM writeMemoryParam;
		writeMemoryParam.ClientBufferAddress = (DWORD64)&value;
		writeMemoryParam.TargetBufferAddress = (DWORD64)&x;
		writeMemoryParam.Size = sizeof(value);

		DeviceIoControl(
			h,
			WRITE_MEMORY_REQUEST,
			&writeMemoryParam,
			sizeof(writeMemoryParam),
			nullptr,
			0,
			&IoSize,
			NULL);
		std::printf("WRITE_MEMORY_REQUEST\n");

		CloseHandle(h);
	}

	getchar();
}