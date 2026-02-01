// Remote execution runtime utilities and declarations
// Ammar by7ebko ;)

#pragma once

#include <Windows.h>
#include <Psapi.h>
#include <cstdint>

#define DECLARE_WINAPI_FUNC(funcname) decltype(&funcname) funcname = &::funcname
#define DECLARE_MRKAPI_FUNC(funcname) decltype(&mrk::remote_detail::funcname) funcname = &mrk::remote_detail::funcname

namespace mrk {

	struct WinAPI {
		DECLARE_WINAPI_FUNC(LoadLibraryA);
		DECLARE_WINAPI_FUNC(GetProcAddress);
		DECLARE_WINAPI_FUNC(K32GetModuleInformation);
		DECLARE_WINAPI_FUNC(GetCurrentProcess);
		DECLARE_WINAPI_FUNC(MessageBoxA);
		DECLARE_WINAPI_FUNC(wsprintfA);
		DECLARE_WINAPI_FUNC(CreateFileA);
		DECLARE_WINAPI_FUNC(GetFileSizeEx);
		DECLARE_WINAPI_FUNC(ReadFile);
		DECLARE_WINAPI_FUNC(CloseHandle);
		DECLARE_WINAPI_FUNC(VirtualAlloc);
		DECLARE_WINAPI_FUNC(VirtualFree);
	};

	namespace remote_detail {

		/* API */
		struct File {
			uint8_t* bytes;
			size_t sz;
		};

		File* __stdcall ReadFile(const char* path);

	} // namespace remote_detail

	struct MRKAPI {
		/// Currently invalid in remote process
		/// Use winapi.GetCurrentProcess()
		HANDLE hProc;

		// Trampoline map
		// 16 should be enough for now
		static constexpr size_t TRAMPOLINE_MAP_SIZE = 16;
		typedef void* TrampolineMap[TRAMPOLINE_MAP_SIZE];
		TrampolineMap trampolines;

		/// REMOTE_PERSISTENT_FUNCTION
		DECLARE_MRKAPI_FUNC(ReadFile);
	};

	struct RemoteRuntimeData {
		WinAPI winapi;
		MRKAPI mrkapi;

		/// For use by printf, etc
		/// We can also use mrk::stackalloc(xxx) for dynamic allocation of buffers
		char stack[0x1000];
	};

} // namespace mrk

// Virtual stack space
#define RUNTIME_STACK(offset, ty) reinterpret_cast<ty*>(reinterpret_cast<uintptr_t>(runtimeData->stack) + offset)
