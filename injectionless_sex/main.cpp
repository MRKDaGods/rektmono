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
	auto* monoModuleInfo = REMOTE_ARG(2, MODULEINFO*);
	auto* outMonoHandle = REMOTE_ARG(3, HMODULE*);
	auto** outMonoBaseAddr = REMOTE_ARG(4, void**);

	HMODULE hMono = runtimeData->winapi.LoadLibraryA(monoPath);
	if (!hMono) {
		return 1;
	}

	// My dumbass forgot that we dont allocate stack space
	// Spent ~1hr figuring out why K32GetModuleInformation was crashing
	// TLDR: Use auto* monoModuleInfo = REMOTE_ARG(3, MODULEINFO*); instead of allocating it on stack

	// TODO: Disasm method at runtime & allocate sufficient stack space

	// Get mono base addr
	if (!runtimeData->winapi.K32GetModuleInformation(
		runtimeData->winapi.GetCurrentProcess(),
		hMono,
		monoModuleInfo,
		sizeof(MODULEINFO)
	)) {
		return 2;
	}

	*outMonoHandle = hMono;
	*outMonoBaseAddr = monoModuleInfo->lpBaseOfDll;
	return 0;
}

typedef struct _MonoImage MonoImage;
typedef int MonoImageOpenStatus;
typedef MonoImage* (__fastcall* mono_image_open_from_data_t)(char* data, unsigned int data_len, int need_copy, MonoImageOpenStatus* status);
typedef MonoImage* (__fastcall* mono_image_open_from_data_internal_t)(void* alc, char* data, unsigned int data_len, int need_copy, MonoImageOpenStatus* status, int refonly, int metadata_only, const char* name, const char* filename);
typedef MonoImage* (__fastcall* do_mono_image_open_t)(void* alc, const char* fname, MonoImageOpenStatus* status, int care_about_cli, int care_about_pecoff, int refonly, int metadata_only, int load_from_context);

REMOTE_FUNCTION(ResolveMonoProcs) {
	auto* runtimeData = REMOTE_RUNTIME_DATA_ARG();

	// mono_image_open_from_data is exported
	auto hMono = REMOTE_ARG(1, HMODULE);
	auto monoImageOpenFromDataProcName = REMOTE_ARG(2, const char*);
	auto* outMonoImageOpenFromData = REMOTE_ARG(3, mono_image_open_from_data_t*);

	// In newer Unity, mono inlines mono_image_open_from_data_internal inside its callers
	// Crazy

	*outMonoImageOpenFromData = reinterpret_cast<mono_image_open_from_data_t>(
		runtimeData->winapi.GetProcAddress(
			hMono,
			monoImageOpenFromDataProcName
		)
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
	HMODULE hMono;
	void* monoBaseAddr;
	DWORD result;
	if (!mrk::callRemoteFunction(
		procInfo.hProcess,
		procInfo.hThread,
		runtimeDataAddr,
		LoadMono,
		&result,
		/* 1 */ 	MONO_RELV_PATH,
		/* 2 */		mrk::remote::stackalloc<MODULEINFO>(),
		/* 3 */		mrk::remote::out(&hMono),
		/* 4 */		mrk::remote::out(&monoBaseAddr)
	) || result != 0) {
		LOG("Failed to load mono into target process. Result: %lu", result);
		mrk::killProcess(procInfo.dwProcessId);
		CloseHandle(procInfo.hThread);
		CloseHandle(procInfo.hProcess);
		return 1;
	}

	LOG("Mono loaded at 0x%p", monoBaseAddr);
	LOG("Mono module handle: %p", (void*)hMono);

	// Resolve mono procs
	mono_image_open_from_data_t monoImageOpenFromData;
	if (!mrk::callRemoteFunction(
		procInfo.hProcess,
		procInfo.hThread,
		runtimeDataAddr,
		ResolveMonoProcs,
		&result,
		/* 1 */		hMono,
		/* 2 */		"mono_image_open_from_data",
		/* 3 */		mrk::remote::out(&monoImageOpenFromData)
	) || result != 0) {
		LOG("Failed to resolve mono procs. Result: %lu", result);
		mrk::killProcess(procInfo.dwProcessId);
		CloseHandle(procInfo.hThread);
		CloseHandle(procInfo.hProcess);
		return 1;
	}

	LOG("Resolved mono_image_open_from_data at address: %p", (void*)monoImageOpenFromData);

	CloseHandle(procInfo.hThread);
	CloseHandle(procInfo.hProcess);
	return 0;
}