#include "remote/runtime.h"
#include "remote/runtime_data.h"
#include "remote/hook.h"
#include "mono.h"

#include <filesystem>
#include <bit>

// Ty pooks for contributing with ur gfx assignment <3
#define TARGET_PROC_DIR "C:\\Users\\mamar\\Desktop\\Build"
#define TARGET_PROC_NAME "UnityAssignment.exe"
#define MONO_RELV_PATH "MonoBleedingEdge\\EmbedRuntime\\mono-2.0-bdwgc.dll"

//REMOTE_HOOKED_FUNCTION(HookedMonoImageOpenFromData, char* data, unsigned int data_len, int need_copy, MonoImageOpenStatus* status, int refonly, const char* name) {
//	auto* runtimeData = REMOTE_HOOKED_RUNTIME_DATA();
//	runtimeData->winapi.MessageBoxA(nullptr, name, "XXX", MB_OK);
//	return 0;
//}

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

	// Allocate hook function
	// String references will be automatically patched
	//mrk::PersistentRemoteFunction remoteHookedFunc;
	//mrk::PersistentFunctionStringContext stringContext;
	//if (!mrk::allocatePersistentRemoteFunction(
	//	procInfo.hProcess,
	//	reinterpret_cast<uint8_t*>(&HookedMonoImageOpenFromData),
	//	runtimeDataAddr,
	//	&remoteHookedFunc,
	//	&stringContext // keep track for cleanup
	//)) {
	//	LOG("Failed to allocate persistent remote function");
	//	mrk::killProcess(procInfo.dwProcessId);
	//	CloseHandle(procInfo.hThread);
	//	CloseHandle(procInfo.hProcess);
	//	return 1;
	//}

	//LOG("Allocated hooked function at 0x%p", (void*)remoteHookedFunc);
	//LOG("Patched %zu string references", stringContext.strings.size());

	//// Hook
	//mrk::remoteHook(procInfo.hProcess, monoImageOpenFromDataWithName, remoteHookedFunc, nullptr);

	// mrk::freePersistentFunctionStrings(procInfo.hProcess, stringContext);

	// kill it
	mrk::killProcess(procInfo.dwProcessId);

	CloseHandle(procInfo.hThread);
	CloseHandle(procInfo.hProcess);
	return 0;
}