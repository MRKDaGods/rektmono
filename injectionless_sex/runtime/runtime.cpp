#include "runtime.h"
#include "../logger.h"

#include <TlHelp32.h>

namespace mrk {
	HANDLE getProcessMainThread(HANDLE hProc) {
		if (!hProc) {
			VLOG("getProcessMainThread: Invalid process handle");
			return nullptr;
		}

		DWORD procId = GetProcessId(hProc);
		if (!procId) {
			VLOG("getProcessMainThread: Failed to get process ID. Error: %lu", GetLastError());
			return nullptr;
		}

		VLOG("getProcessMainThread: Looking for main thread of process ID: %lu", procId);

		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (hSnapshot == INVALID_HANDLE_VALUE) {
			VLOG("getProcessMainThread: Failed to create thread snapshot. Error: %lu", GetLastError());
			return nullptr;
		}

		THREADENTRY32 threadEntry;
		threadEntry.dwSize = sizeof(THREADENTRY32);
		if (!Thread32First(hSnapshot, &threadEntry)) {
			VLOG("getProcessMainThread: Thread32First failed. Error: %lu", GetLastError());
			CloseHandle(hSnapshot);
			return nullptr;
		}

		do {
			if (threadEntry.th32OwnerProcessID == procId) {
				VLOG("getProcessMainThread: Found thread ID: %lu", threadEntry.th32ThreadID);
				HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadEntry.th32ThreadID);
				if (hThread) {
					VLOG("getProcessMainThread: Successfully opened thread handle: %p", hThread);
				} else {
					VLOG("getProcessMainThread: Failed to open thread. Error: %lu", GetLastError());
				}
				CloseHandle(hSnapshot);
				return hThread;
			}
		} while (Thread32Next(hSnapshot, &threadEntry));

		VLOG("getProcessMainThread: No threads found for process ID: %lu", procId);
		CloseHandle(hSnapshot);
		return nullptr;
	}

	// The way we will be executing remote functions
	// is by hijacking threads, cuz thats cool
	bool executeRemoteFunction(HANDLE hProc, HANDLE hThread, RemoteFunction function, RemoteFunctionArgs& args,
		PDWORD result, size_t estimatedFunctionSize) {
		LOG("Starting remote function execution...");
		
		if (!hProc || !function) {
			LOG("Invalid parameters: hProc=%p, function=%p", hProc, function);
			return false;
		}

		if (!hThread) {
			LOG("No thread handle provided, getting main thread...");
			hThread = getProcessMainThread(hProc);
			if (!hThread) {
				LOG("Failed to get main thread of target process.");
				return false;
			}
			LOG("Successfully obtained main thread handle: %p", hThread);
		} else {
			LOG("Using provided thread handle: %p", hThread);
		}

		// Try allocate execution context in remote process
		LOG("Allocating execution context in remote process (size: %zu bytes)...", sizeof(RemoteExecutionContext));
		void* contextBase = VirtualAllocEx(
			hProc,
			nullptr,
			sizeof(RemoteExecutionContext),
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE
		);

		if (!contextBase) {
			LOG("Failed to allocate execution context. Error: %lu", GetLastError());
			return false;
		}
		LOG("Execution context allocated at: %p", contextBase);

		// Prepare execution context
		LOG("Preparing execution context...");
		RemoteExecutionContext execContext;
		ZeroMemory(&execContext, sizeof(execContext));

		// Patch shellcode
		VLOG("Setting up shellcode patches...");
		ShellcodePatchSetup patchSetup;
		patchSetup.remoteFunctionAddress = reinterpret_cast<void*>(
			reinterpret_cast<uintptr_t>(contextBase) + offsetof(RemoteExecutionContext, remoteFunction));

		patchSetup.paramsAddress = reinterpret_cast<void*>(
			reinterpret_cast<uintptr_t>(contextBase) + offsetof(RemoteExecutionContext, args));

		patchSetup.returnCodeAddress = reinterpret_cast<void*>(
			reinterpret_cast<uintptr_t>(contextBase) + offsetof(RemoteExecutionContext, returnCode));

		patchSetup.completionFlagAddress = reinterpret_cast<void*>(
			reinterpret_cast<uintptr_t>(contextBase) + offsetof(RemoteExecutionContext, completionFlag));

		VLOG("Patch addresses - Function: %p, Params: %p, ReturnCode: %p, CompletionFlag: %p",
			patchSetup.remoteFunctionAddress, patchSetup.paramsAddress, 
			patchSetup.returnCodeAddress, patchSetup.completionFlagAddress);

		VLOG("Patching shellcode...");
		patchShellcode(execContext.shellcode, patchSetup);

		// Copy function and args
		VLOG("Copying function (%zu bytes) and args to execution context...", 
			min(estimatedFunctionSize, REMOTE_FUNCTION_SIZE));
		VLOG("Args: arg[0]=0x%p, arg[1]=0x%p, arg[2]=0x%p, arg[3]=0x%p", 
			(void*)args.args[0], (void*)args.args[1], (void*)args.args[2], (void*)args.args[3]);
		memcpy(&execContext.remoteFunction, reinterpret_cast<void*>(function), min(estimatedFunctionSize, REMOTE_FUNCTION_SIZE));
		memcpy(&execContext.args, reinterpret_cast<void*>(&args), sizeof(RemoteFunctionArgs));

		// Write context to remote process
		LOG("Writing execution context to remote process...");
		if (!WriteProcessMemory(hProc, contextBase, &execContext, sizeof(execContext), nullptr)) {
			LOG("Failed to write execution context. Error: %lu", GetLastError());
			VirtualFreeEx(hProc, contextBase, 0, MEM_RELEASE);
			return false;
		}
		VLOG("Execution context written successfully.");

		// Ensure cache is flushed
		VLOG("Flushing instruction cache...");
		if (!FlushInstructionCache(hProc, contextBase, sizeof(execContext))) {
			LOG("Failed to flush instruction cache. Error: %lu", GetLastError());
			VirtualFreeEx(hProc, contextBase, 0, MEM_RELEASE);
			return false;
		}
		VLOG("Instruction cache flushed successfully.");

		// Hijack thread
		// Suspend, get context, set RIP to shellcode, set context, resume
		LOG("Suspending target thread...");
		if (SuspendThread(hThread) == (DWORD)-1) {
			LOG("Failed to suspend thread. Error: %lu", GetLastError());
			VirtualFreeEx(hProc, contextBase, 0, MEM_RELEASE);
			return false;
		}
		VLOG("Thread suspended successfully.");

		VLOG("Getting thread context...");
		CONTEXT threadCtx;
		ZeroMemory(&threadCtx, sizeof(threadCtx));
		threadCtx.ContextFlags = CONTEXT_FULL;

		if (!GetThreadContext(hThread, &threadCtx)) {
			LOG("Failed to get thread context. Error: %lu", GetLastError());
			ResumeThread(hThread);
			VirtualFreeEx(hProc, contextBase, 0, MEM_RELEASE);
			return false;
		}
		LOG("Thread context retrieved. Original RIP: %p", (void*)threadCtx.Rip);

		// Save original context before modification
		CONTEXT originalThreadCtx = threadCtx;

		// Set RIP to shellcode
		uintptr_t shellcodeAddress = reinterpret_cast<uintptr_t>(
			reinterpret_cast<uint8_t*>(contextBase) + offsetof(RemoteExecutionContext, shellcode));
		threadCtx.Rip = shellcodeAddress;
		
		LOG("Setting thread RIP to shellcode at: %p", (void*)shellcodeAddress);
		if (!SetThreadContext(hThread, &threadCtx)) {
			LOG("Failed to set thread context. Error: %lu", GetLastError());
			ResumeThread(hThread);
			VirtualFreeEx(hProc, contextBase, 0, MEM_RELEASE);
			return false;
		}
		VLOG("Thread context set successfully.");

		LOG("Resuming thread to execute shellcode...");
		ResumeThread(hThread);

		// Wait for completion
		LOG("Waiting for shellcode completion...");
		DWORD completionFlag = 0;
		int pollCount = 0;
		do {
			Sleep(100);
			pollCount++;
			if (pollCount % 100 == 0) {
				VLOG("Still waiting for completion... (poll count: %d)", pollCount);
			}
		} while (ReadProcessMemory(
			hProc,
			patchSetup.completionFlagAddress,
			&completionFlag,
			sizeof(DWORD),
			nullptr
		) && completionFlag != COMPLETION_FLAG_VALUE);

		// RPM failed?
		if (completionFlag != COMPLETION_FLAG_VALUE) {
			LOG("Shellcode did not complete successfully. Completion flag: 0x%08X", completionFlag);
			VirtualFreeEx(hProc, contextBase, 0, MEM_RELEASE);
			return false;
		}
		LOG("Shellcode completed successfully after %d polls.", pollCount);

		// Read return code
		VLOG("Reading return code...");
		DWORD returnCode = 0;
		if (!ReadProcessMemory(
			hProc,
			patchSetup.returnCodeAddress,
			&returnCode,
			sizeof(DWORD),
			nullptr
		)) {
			LOG("Failed to read shellcode return code. Error: %lu", GetLastError());
			VirtualFreeEx(hProc, contextBase, 0, MEM_RELEASE);
			return false;
		}
		LOG("Return code: 0x%08X (%u)", returnCode, returnCode);

		// Restore original context
		VLOG("Suspending thread for context restoration...");
		if (SuspendThread(hThread) == (DWORD)-1) {
			LOG("Failed to suspend thread for restoration. Error: %lu", GetLastError());
			VirtualFreeEx(hProc, contextBase, 0, MEM_RELEASE);
			return false;
		}

		VLOG("Restoring original thread context (RIP: %p)...", (void*)originalThreadCtx.Rip);
		if (!SetThreadContext(hThread, &originalThreadCtx)) {
			LOG("Failed to restore thread context. Error: %lu", GetLastError());
			ResumeThread(hThread);
			VirtualFreeEx(hProc, contextBase, 0, MEM_RELEASE);
			return false;
		}
		VLOG("Thread context restored successfully.");

		VLOG("Resuming thread...");
		ResumeThread(hThread);

		// Return result
		if (result) {
			*result = returnCode;
			VLOG("Result stored: 0x%08X", *result);
		}

		// Free context
		VLOG("Freeing execution context...");
		VirtualFreeEx(hProc, contextBase, 0, MEM_RELEASE);
		LOG("Remote function execution completed successfully.");
		return true;
	}
}