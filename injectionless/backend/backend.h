#pragma once

// Kernel/User

#include <Windows.h>

#define MRK_USER_MODE
// #define MRK_KERNEL_MODE

namespace mrk::backend {

	HANDLE openProcess(
		DWORD processId,
		DWORD dwDesiredAccess
	);

	HANDLE openThread(
		DWORD threadId,
		DWORD dwDesiredAccess
	);

	void closeHandle(
		HANDLE hObject
	);

	BOOL writeProcessMemory(
		HANDLE hProcess,
		LPVOID lpBaseAddress,
		LPCVOID lpBuffer,
		SIZE_T nSize,
		SIZE_T* lpNumberOfBytesWritten
	);

	BOOL readProcessMemory(
		HANDLE hProcess,
		LPCVOID lpBaseAddress,
		LPVOID lpBuffer,
		SIZE_T nSize,
		SIZE_T* lpNumberOfBytesRead
	);

} // namespace mrk::backend