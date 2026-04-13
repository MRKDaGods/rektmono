#include "runtime.h"
#include "../logger.h"
#include "../utils/utils.h"

#include <TlHelp32.h>
#include <unordered_set>

namespace mrk {

	/// Internally keep track of suspended procs
	/// Winapi doesnt provide access to the suspension semaphore
	std::unordered_set<DWORD> g_SuspendedPIDs;

	void setSuspended(DWORD pid, bool suspended) { if (suspended) g_SuspendedPIDs.insert(pid); else g_SuspendedPIDs.erase(pid); }
	bool isSuspended(DWORD pid) { return g_SuspendedPIDs.find(pid) != g_SuspendedPIDs.end(); }

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
				}
				else {
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
		}
		else {
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
		DWORD pid = GetProcessId(hProc);
		if (!isSuspended(pid)) {
			LOG("Suspending target thread...");
			if (SuspendThread(hThread) == (DWORD)-1) {
				LOG("Failed to suspend thread. Error: %lu", GetLastError());
				VirtualFreeEx(hProc, contextBase, 0, MEM_RELEASE);
				return false;
			}

			setSuspended(pid, true);
			VLOG("Thread suspended successfully.");
		}

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
		setSuspended(pid, false);

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
		setSuspended(pid, true);

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
		setSuspended(pid, false);

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

	DWORD getProcessPID(const std::string& processName) {
		LOG("Getting PID for process name: %s", processName.c_str());

		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnapshot == INVALID_HANDLE_VALUE) {
			LOG("Failed to create process snapshot. Error: %lu", GetLastError());
			return 0;
		}

		PROCESSENTRY32 procEntry;
		procEntry.dwSize = sizeof(PROCESSENTRY32);
		if (!Process32First(hSnapshot, &procEntry)) {
			LOG("Process32First failed. Error: %lu", GetLastError());
			CloseHandle(hSnapshot);
			return 0;
		}

		do {
			if (processName == procEntry.szExeFile) {
				DWORD pid = procEntry.th32ProcessID;
				VLOG("Found process '%s' with PID: %lu", processName.c_str(), pid);
				CloseHandle(hSnapshot);
				return pid;
			}
		} while (Process32Next(hSnapshot, &procEntry));

		VLOG("Process '%s' not found.", processName.c_str());
		CloseHandle(hSnapshot);
		return 0;
	}

	bool killProcess(DWORD pid) {
		if (pid == 0) return false;

		HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
		if (!hProc) {
			LOG("Failed to open process %lu for termination. Error: %lu", pid, GetLastError());
			return false;
		}

		if (!TerminateProcess(hProc, 0)) {
			LOG("Failed to terminate process %lu. Error: %lu", pid, GetLastError());
			CloseHandle(hProc);
			return false;
		}

		CloseHandle(hProc);
		return true;
	}

	bool createSuspendedProcess(const std::string& applicationPath, ProcessInfo* procInfo) {
		STARTUPINFOA si;
		ZeroMemory(&si, sizeof(si));
		si.cb = sizeof(si);

		PROCESS_INFORMATION pi;
		ZeroMemory(&pi, sizeof(pi));

		if (!CreateProcessA(
			applicationPath.c_str(),
			nullptr,
			nullptr,
			nullptr,
			FALSE,
			CREATE_SUSPENDED,
			nullptr,
			nullptr,
			&si,
			&pi
		)) {
			return false;
		}

		if (procInfo) {
			*procInfo = pi;
		}
		else {
			// If no proc info supplied, dont leak handles
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
		}

		// Mark suspended
		setSuspended(pi.dwProcessId, true);
		return true;
	}

	RemoteRuntimeData createRuntimeData(HANDLE hProc) {
		RemoteRuntimeData data{};
		data.mrkapi.hProc = hProc;
		ZeroMemory(data.mrkapi.trampolines, sizeof(data.mrkapi.trampolines));
		return data;
	}

	bool allocateRuntimeData(HANDLE hProc, void** outDataAddress) {
		if (!hProc || !outDataAddress) return false;

		void* remoteAddr = VirtualAllocEx(hProc, nullptr, sizeof(RemoteRuntimeData), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!remoteAddr) {
			LOG("Failed to allocate runtime data. Error: %lu", GetLastError());
			return false;
		}

		RemoteRuntimeData runtimeData = createRuntimeData(hProc);

		// Allocate local API functions
		if (!detail::allocateLocalAPIFunctions(hProc, runtimeData, remoteAddr)) {
			LOG("Failed to allocate local API functions");
			VirtualFreeEx(hProc, remoteAddr, 0, MEM_RELEASE);
			return false;
		}

		// Write runtime data
		if (!WriteProcessMemory(hProc, remoteAddr, &runtimeData, sizeof(RemoteRuntimeData), nullptr)) {
			LOG("Failed to write runtime data. Error: %lu", GetLastError());
			return false;
		}
		VLOG("Allocated runtime data at 0x%p", remoteAddr);

		*outDataAddress = remoteAddr;
		return true;
	}

	bool allocatePersistentRemoteFunction(
		HANDLE hProc,
		PersistentRemoteFunction function,
		void* runtimeDataAddr,
		PersistentRemoteFunction* outFuncBase,
		PersistentFunctionStringContext* outStringContext
	) {
		LOG("Allocating persistent remote function, local addr=0x%p, runtimeData=0x%p", function, runtimeDataAddr);

		// Find function size
		// Just look for PADDING
		// TODO: Update this when IAT fixup is implemented
		size_t funcSize = 0;
		while (function[funcSize++] != 0xCC);
		LOG("Function size=%zu", funcSize);

		printFunctionDisassembly(function);

		// Create a working copy of the function
		uint8_t* funcCopy = new uint8_t[funcSize];
		memcpy(funcCopy, function, funcSize);
		
		// Patch runtime data placeholder
		// Compiler already hardcodes the offsets so just look for DIEAFIFI..
		// Assume RemoteRuntimeData never exceeds FFFFFFFF bytes
		static_assert(sizeof(RemoteRuntimeData) <= 0xFFFFFFFF, "RemoteRuntimeData too big lol");
		constexpr uintptr_t upperPlaceholder = EMBEDDED_RUNTIME_DATA_PLACEHOLDER >> 32; // 4 bytes right

		if (funcSize >= sizeof(uintptr_t)) {
			for (size_t i = 0; i + sizeof(uintptr_t) <= funcSize; i++) {
				uintptr_t* potentialPlaceholder = reinterpret_cast<uintptr_t*>(funcCopy + i);
				if (!isAddressReadable(static_cast<void*>(potentialPlaceholder))) {
					continue;
				}

				if ((*potentialPlaceholder >> 32) == upperPlaceholder) {
					uintptr_t delta = *potentialPlaceholder - EMBEDDED_RUNTIME_DATA_PLACEHOLDER;
					uintptr_t newDataAddr = reinterpret_cast<uintptr_t>(runtimeDataAddr) + delta;
					LOG("Found embedded runtime data placeholder at offset 0x%zX, patching with 0x%zX", i, newDataAddr);
					*potentialPlaceholder = newDataAddr;
				}
			}
		}

		// Allocate in remote process
		size_t allocSize = static_cast<size_t>(std::ceilf(funcSize / 4096.f)) * 4096;
		void* funcBase = VirtualAllocEx(hProc, nullptr, allocSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!funcBase) {
			LOG("Failed to allocate remote function. Error: %lu", GetLastError());
			delete[] funcCopy;
			return false;
		}
		LOG("Allocated %zu bytes at 0x%p", allocSize, funcBase);

		// Scan and patch string references
		PersistentFunctionStringContext stringContext;
		
		// ana 7omarrrr
		// This patches funcCopy directly
		if (!scanAndPatchStrings(hProc,
								 funcBase,	// Remote alloc base
								 function,	// Original func buffer
								 funcCopy,	// Patch buffer
								 funcSize,
								 &stringContext)) {
			LOG("Failed to patch string references");
			delete[] funcCopy;
			return false;
		}

		// Write patched function
		if (!WriteProcessMemory(hProc, funcBase, funcCopy, funcSize, nullptr)) {
			LOG("Failed to write remote function. Error: %lu", GetLastError());
			delete[] funcCopy;
			VirtualFreeEx(hProc, funcBase, 0, MEM_RELEASE);
			freePersistentFunctionStrings(hProc, stringContext);
			return false;
		}
		LOG("Written patched remote function");

		delete[] funcCopy;

		if (outFuncBase) {
			*outFuncBase = reinterpret_cast<PersistentRemoteFunction>(funcBase);
		}

		if (outStringContext) {
			*outStringContext = stringContext;
		}

		return true;
	}

	namespace detail {

		bool allocateLocalAPIFunctions(
			HANDLE hProc,
			RemoteRuntimeData& localData,
			void* remoteDataAddr
		) {
			// ReadFile			<----- START
			// ReadFile2
			// .....
			// END OF MRKAPI	<----- END

			for (uintptr_t offset = offsetof(MRKAPI, ReadFile); offset < sizeof(MRKAPI); offset += sizeof(void*)) {
				PersistentRemoteFunction* funcPtr = reinterpret_cast<PersistentRemoteFunction*>(
					reinterpret_cast<uintptr_t>(&localData.mrkapi) + offset
				);
				if (!allocatePersistentRemoteFunction(
					hProc,
					*funcPtr,
					remoteDataAddr,
					funcPtr
				)) {
					LOG("Failed to allocate persistent remote function for MRKAPI offset 0x%zX", offset);
					return false;
				}
			}

			return true;
		}

	} // namespace detail

} // namespace mrk
