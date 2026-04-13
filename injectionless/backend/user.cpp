#include "backend.h"

#ifdef MRK_USER_MODE

namespace mrk::backend {

	HANDLE openProcess(
		DWORD processId,
		DWORD dwDesiredAccess
	) {
		return OpenProcess(dwDesiredAccess, FALSE, processId);
	}

	HANDLE openThread(
		DWORD threadId,
		DWORD dwDesiredAccess
	) {
		return OpenThread(dwDesiredAccess, FALSE, threadId);
	}

	void closeHandle(
		HANDLE hObject
	) {
		CloseHandle(hObject);
	}

	BOOL writeProcessMemory(
		HANDLE hProcess,
		LPVOID lpBaseAddress,
		LPCVOID lpBuffer,
		SIZE_T nSize,
		SIZE_T* lpNumberOfBytesWritten
	) {
		return WriteProcessMemory(
			hProcess,
			lpBaseAddress,
			lpBuffer,
			nSize,
			lpNumberOfBytesWritten
		);
	}

	BOOL readProcessMemory(
		HANDLE hProcess,
		LPCVOID lpBaseAddress,
		LPVOID lpBuffer,
		SIZE_T nSize,
		SIZE_T* lpNumberOfBytesRead
	) {
		return ReadProcessMemory(
			hProcess,
			lpBaseAddress,
			lpBuffer,
			nSize,
			lpNumberOfBytesRead
		);
	}

} // namespace mrk::backend

#endif // MRK_USER_MODE