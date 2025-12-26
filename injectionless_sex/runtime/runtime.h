#pragma once

#include "../shellcode/shellcode.h"
#include "remote_args.h"
#include "remote_call.h"
#include "remote_api.h"

#include <Windows.h>
#include <cstdint>
#include <string>

namespace mrk {
	/// Short hand for PROCESS_INFORMATION
	typedef PROCESS_INFORMATION ProcessInfo;

	/// Assume 4KB is enough for any remote function
	constexpr size_t REMOTE_FUNCTION_SIZE = 0x1000;

	/// Remote execution context structure
	struct RemoteExecutionContext {
		uint8_t shellcode[EXEC_SHELLCODE_SIZE];
		RemoteFunctionArgs args;
		uint8_t remoteFunction[REMOTE_FUNCTION_SIZE];
		DWORD returnCode;
		DWORD completionFlag;
	};

	/// Execute a remote function in the target process
	bool executeRemoteFunction(HANDLE hProc, HANDLE hThread, RemoteFunction function, RemoteFunctionArgs& args, 
		PDWORD result = nullptr, size_t estimatedFunctionSize = -1);

	/// Get process PID by name
	DWORD getProcessPID(const std::string& processName);
	
	/// Kill process by PID
	bool killProcess(DWORD pid);
	
	/// Create a suspended process given an application path
	bool createSuspendedProcess(const std::string& applicationPath, ProcessInfo* procInfo);

	/// Allocate runtime data in remote process (for internal use)
	bool allocateRuntimeData(HANDLE hProc, void** outRemoteAddress);

	/// Check if we are supported on this architecture
	inline bool isInjectionlessSexSupported() {
#ifdef _M_X64
		return true;
#else
		return false;
#endif
	}
}