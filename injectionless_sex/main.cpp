#include "runtime/runtime.h"
#include "runtime/remote_runtime_data.h"

#include <filesystem>

// Ty pooks for contributing with ur gfx assignment <3
#define TARGET_PROC_DIR "C:\\Users\\mamar\\Desktop\\Build"
#define TARGET_PROC_NAME "UnityAssignment.exe"
#define MONO_RELV_PATH "MonoBleedingEdge\\EmbedRuntime\\mono-2.0-bdwgc.dll"

REMOTE_FUNCTION(LoadMono) {
	auto* runtimeData = REMOTE_RUNTIME_DATA_ARG();
	auto* monoPath = REMOTE_ARG(1, const char*);
	auto* monoLoadedFmt = REMOTE_ARG(2, const char*);
	auto* monoModuleInfo = REMOTE_ARG(3, MODULEINFO*);

	HMODULE hMono = runtimeData->winapi.LoadLibraryA(monoPath);
	if (!hMono) {
		return 1;
	}

	// My dumbass forgot that we dont allocate stack space
	// Spent ~1hr figuring out why K32GetModuleInformation was crashing
	// TLDR: Use auto* monoModuleInfo = REMOTE_ARG(3, MODULEINFO*); instead of allocating it on stack

	// Get mono base addr
	if (!runtimeData->winapi.K32GetModuleInformation(
		runtimeData->winapi.GetCurrentProcess(),
		hMono,
		monoModuleInfo,
		sizeof(MODULEINFO)
	)) {
		return 2;
	}

	runtimeData->winapi.wsprintfA(
		runtimeData->buffer,
		monoLoadedFmt,
		monoModuleInfo->lpBaseOfDll
	);

	runtimeData->winapi.MessageBoxA(
		NULL,
		runtimeData->buffer,
		nullptr,
		MB_OK
	);

	return 0;
}

int main() {
	LOG("Injectionless sex - %s", __TIMESTAMP__);

	if (!mrk::isInjectionlessSexSupported()) {
		LOG("Injectionless sex is not supported on this architecture.");
		return 1;
	}

	// Check if running
	DWORD targetPid = mrk::getProcessPID(TARGET_PROC_NAME);
	if (targetPid != 0) {
		LOG("Target process is running with PID: %lu, killing...", targetPid);
		if (mrk::killProcess(targetPid)) {
			LOG("Target process killed successfully.");
		} else {
			LOG("Failed to kill target process.");
			return 1;
		}
	}
	else {
		LOG("Target process is not running.");
	}

	// Start suspended process
	std::filesystem::path procPath = TARGET_PROC_DIR / std::filesystem::path(TARGET_PROC_NAME);
	LOG("Creating suspended target process: %s", procPath.string().c_str()); // procPath.c_str() isnt working directly?
	mrk::ProcessInfo procInfo;
	if (!mrk::createSuspendedProcess(procPath.string(), &procInfo)) {
		LOG("Failed to create suspended target process.");
		return 1;
	}
	LOG("Suspended target process created successfully. PID: %lu", procInfo.dwProcessId);

	// Allocate remote runtime data
	void* runtimeDataAddr = nullptr;
	if (!mrk::allocateRuntimeData(procInfo.hProcess, &runtimeDataAddr)) {
		LOG("Failed to allocate remote runtime data.");
		mrk::killProcess(procInfo.dwProcessId);
		CloseHandle(procInfo.hThread);
		CloseHandle(procInfo.hProcess);
		return 1;
	}

	// Load up mono
	mrk::callRemoteFunction(
		procInfo.hProcess,
		procInfo.hThread,
		runtimeDataAddr,
		LoadMono,
		MONO_RELV_PATH,
		"Mono loaded at address: %p", 
		mrk::remoteBuffer<MODULEINFO>());

	CloseHandle(procInfo.hThread);
	CloseHandle(procInfo.hProcess);
	return 0;
}