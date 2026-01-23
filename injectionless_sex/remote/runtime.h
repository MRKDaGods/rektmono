#pragma once

#include "../shellcode/shellcode.h"
#include "args.h"
#include "call.h"
#include "winapi.h"
#include "string_patch.h"

#include <Windows.h>
#include <cstdint>
#include <string>

namespace mrk {

	/// Short hand for PROCESS_INFORMATION
	typedef PROCESS_INFORMATION ProcessInfo;

	/// Assume 4KB is enough for any remote function
	constexpr size_t REMOTE_FUNCTION_SIZE = 0x1000;
	typedef uint8_t RemoteFunctionBuffer[REMOTE_FUNCTION_SIZE];
	typedef uint8_t* PersistentRemoteFunction;

	/// Remote execution context structure
	struct RemoteExecutionContext {
		uint8_t shellcode[EXEC_SHELLCODE_SIZE];
		RemoteFunctionArgs args;
		RemoteFunctionBuffer remoteFunction;
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

	/// Allocates a persistent remote function for hooking, etc
	/// Automatically patches string references to point to remote memory
	bool allocatePersistentRemoteFunction(
		HANDLE hProc, 
		PersistentRemoteFunction function, 
		void* runtimeDataAddr, 
		PersistentRemoteFunction* outFuncBase,
		PersistentFunctionStringContext* outStringContext = nullptr
	);

	/// Debug purposes
	void printFunctionDisassembly(void* function);

	/// Check if we are supported on this architecture
	inline bool isInjectionlessSexSupported() {
#ifdef _M_X64
		return true;
#else
		return false;
#endif
	}

}