#pragma once

#include "../shellcode/shellcode.h"
#include "remote_args.h"
#include "remote_string.h"
#include "remote_call.h"
#include "remote_api.h"

#include <Windows.h>
#include <cstdint>

namespace mrk {
	// Assume 4KB is enough for any remote function
	constexpr size_t REMOTE_FUNCTION_SIZE = 0x1000;

	// Remote execution context structure
	struct RemoteExecutionContext {
		uint8_t shellcode[EXEC_SHELLCODE_SIZE];
		RemoteFunctionArgs args;
		uint8_t remoteFunction[REMOTE_FUNCTION_SIZE];
		DWORD returnCode;
		DWORD completionFlag;
	};

	// Execute a remote function in the target process
	bool executeRemoteFunction(HANDLE hProc, HANDLE hThread, RemoteFunction function, RemoteFunctionArgs& args, 
		PDWORD result = nullptr, size_t estimatedFunctionSize = -1);
}