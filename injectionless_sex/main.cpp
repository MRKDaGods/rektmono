#include "remote/runtime.h"
#include "mono.h"
#include "patch.h"

#include <filesystem>
#include <bit>

// Ty pooks for contributing with ur gfx assignment <3
#define TARGET_PROC_DIR "C:\\Users\\mamar\\Desktop\\Build"
#define TARGET_PROC_NAME "UnityAssignment.exe"
#define MONO_RELV_PATH "MonoBleedingEdge\\EmbedRuntime\\mono-2.0-bdwgc.dll"

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
		}
		else {
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

	// Initialize mono
	mrk::mono::MonoProcs monoProcs;
	ZeroMemory(&monoProcs, sizeof(monoProcs));

	if (!mrk::mono::initialize(procInfo, runtimeDataAddr, MONO_RELV_PATH, &monoProcs)) {
		LOG("Failed to initialize mono");
		mrk::killProcess(procInfo.dwProcessId);
		CloseHandle(procInfo.hThread);
		CloseHandle(procInfo.hProcess);
		return 1;
	}
	LOG("Mono initialized successfully");

	// Initialize hooks!
	if (!mrk::patch::initialize(procInfo, runtimeDataAddr, &monoProcs)) {
		LOG("Failed to initialize hooks");
		mrk::killProcess(procInfo.dwProcessId);
		CloseHandle(procInfo.hThread);
		CloseHandle(procInfo.hProcess);
		return 1;
	}
	LOG("Hooks initialized successfully");

	//// Hook
	//mrk::remoteHook(procInfo.hProcess, monoImageOpenFromDataWithName, remoteHookedFunc, nullptr);

	// kill it
	//mrk::killProcess(procInfo.dwProcessId);

	CloseHandle(procInfo.hThread);
	CloseHandle(procInfo.hProcess);
	return 0;
}