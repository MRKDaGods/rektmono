#include "mono.h"
#include "logger.h"
#include "remote/runtime_data.h"
#include "utils/utils.h"

namespace mrk::mono {

// .text:000000018014E869                 call    do_mono_image_open
#define DO_MONO_IMAGE_OPEN_SIG	"\xE8\x00\x00\x00\x00\x48\x85\xC0\x75\x04\x33\xC0"
#define DO_MONO_IMAGE_OPEN_MASK "x????xxxxxxx"

	bool initialize(
		const ProcessInfo& procInfo,
		void* runtimeDataAddr,
		const char* monoRelativePath,
		MonoProcs* monoProcs
	) {
		if (!procInfo.hProcess || !procInfo.hThread || !runtimeDataAddr || !monoProcs) {
			return false;
		}

		// Load up mono
		HMODULE hMono;
		void* monoBaseAddr;
		size_t monoSz;
		DWORD result;
		if (!callRemoteFunction(
			procInfo.hProcess,
			procInfo.hThread,
			runtimeDataAddr,
			remote_detail::loadMono,
			&result,
			/* 1 */ 	monoRelativePath,
			/* 2 */		remote::stackalloc<MODULEINFO>(),
			/* 3 */		remote::out(&hMono),
			/* 4 */		remote::out(&monoBaseAddr),
			/* 5 */		remote::out(&monoSz)
		) || result != 0) {
			LOG("Failed to load mono into target process. Result: %lu", result);
			return false;
		}

		LOG("Mono loaded at 0x%p", monoBaseAddr);
		LOG("Mono module handle: %p", (void*)hMono);

		// Resolve mono procs
		ZeroMemory(monoProcs, sizeof(MonoProcs));

		// mono_image_open_from_data_with_name
		if (!callRemoteFunction(
			procInfo.hProcess,
			procInfo.hThread,
			runtimeDataAddr,
			remote_detail::resolveMonoImageOpenFromDataWithName,
			&result,
			/* 1 */		hMono,
			/* 2 */		"mono_image_open_from_data_with_name",
			/* 3 */		remote::out(&monoProcs->mono_image_open_from_data_with_name)
		) || result != 0) {
			LOG("Failed to resolve mono_image_open_from_data_with_name. Result: %lu", result);
			return false;
		}

		LOG("Resolved mono_image_open_from_data_with_name at 0x%p", 
			static_cast<void*>(monoProcs->mono_image_open_from_data_with_name));

		if (!detail::resolveDoMonoImageOpen(
			procInfo.hProcess,
			monoBaseAddr,
			monoSz,
			monoProcs
		)) {
			LOG("Failed to resolve do_mono_image_open");
			return false;
		}

		LOG("Resolved do_mono_image_open at 0x%p",
			static_cast<void*>(monoProcs->do_mono_image_open));

		return true;
	}

	namespace detail {

		bool resolveDoMonoImageOpen(
			HANDLE hProc,
			void* monoBaseAddr,
			size_t monoSz,
			MonoProcs* monoProcs
		) {
			// do_mono_image_open
			// call    [rip+disp]
			void* instruction = findRemotePattern(
				hProc,
				monoBaseAddr,
				monoSz,
				DO_MONO_IMAGE_OPEN_SIG,
				sizeof(DO_MONO_IMAGE_OPEN_SIG) - 1,
				DO_MONO_IMAGE_OPEN_MASK
			);

			if (!instruction) {
				LOG("Cant find do_mono_image_open call reference");
				return false;
			}

			uintptr_t instructionAddr = reinterpret_cast<uintptr_t>(instruction);
			LOG("Found do_mono_image_open call reference at 0x%p relv=0x%zX",
				instruction,
				instructionAddr - reinterpret_cast<uintptr_t>(monoBaseAddr));

			int32_t disp;
			if (!ReadProcessMemory(hProc, reinterpret_cast<void*>(instructionAddr + 1), &disp, 4, nullptr)) {
				LOG("Failed to read disp from call reference. Error: %lu", GetLastError());
				return false;
			}
			LOG("Disp=%d", disp);

			monoProcs->do_mono_image_open = reinterpret_cast<do_mono_image_open_t>(instructionAddr + 5 + disp);
			return true;
		}

	} // namespace detail

	// Remote implementations
	namespace remote_detail {

		REMOTE_FUNCTION(loadMono) {
			// TODO: Better stackframe implementation
			auto* runtimeData = REMOTE_RUNTIME_DATA_ARG();
			auto* monoPath = REMOTE_ARG(1, const char*);
			auto* monoModuleInfo = REMOTE_ARG(2, MODULEINFO*);
			auto** outMonoHandle = REMOTE_ARG(3, HMODULE*);
			auto** outMonoBaseAddr = REMOTE_ARG(4, void**);
			auto* outMonoSz = REMOTE_ARG(5, size_t*);

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
			*outMonoSz = monoModuleInfo->SizeOfImage;

			return 0;
		}

		REMOTE_FUNCTION(resolveMonoImageOpenFromDataWithName) {
			auto* runtimeData = REMOTE_RUNTIME_DATA_ARG();

			// mono_image_open_from_data_with_name is exported
			auto* hMono = REMOTE_ARG(1, HMODULE);

			auto* monoImageOpenFromDataWithNameProcName = REMOTE_ARG(2, const char*);
			auto** outMonoImageOpenFromDataWithName = REMOTE_ARG(3, mono_image_open_from_data_with_name_t*);

			// In newer Unity, mono inlines mono_image_open_from_data_internal inside its callers
			// Crazy

			*outMonoImageOpenFromDataWithName = reinterpret_cast<mono_image_open_from_data_with_name_t>(
				runtimeData->winapi.GetProcAddress(hMono, monoImageOpenFromDataWithNameProcName)
			);

			return 0;
		}

	} // namespace remote_detail

} // namespace mrk::mono