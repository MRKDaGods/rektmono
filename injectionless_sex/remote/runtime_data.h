// Remote execution runtime utilities and declarations
// Ammar by7ebko ;)

#pragma once

#include <Windows.h>
#include <Psapi.h>
#include <cstdint>

#define DECLARE_API_FUNC(funcname) decltype(&funcname) funcname = &::funcname

namespace mrk {

	struct WinAPI {
		DECLARE_API_FUNC(LoadLibraryA);
		DECLARE_API_FUNC(GetProcAddress);
		DECLARE_API_FUNC(K32GetModuleInformation);
		DECLARE_API_FUNC(GetCurrentProcess);
		DECLARE_API_FUNC(MessageBoxA);
		DECLARE_API_FUNC(wsprintfA);
		DECLARE_API_FUNC(CreateFileA);
		DECLARE_API_FUNC(GetFileSizeEx);
		DECLARE_API_FUNC(ReadFile);
		DECLARE_API_FUNC(CloseHandle);
		DECLARE_API_FUNC(VirtualAlloc);
		DECLARE_API_FUNC(VirtualFree);
	};

	namespace remote_detail {
		/* API */
		struct File {
			uint8_t* bytes;
			size_t sz;
		};

		File* __stdcall ReadFile(const char* path);
	}

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
		decltype(&mrk::remote_detail::ReadFile) ReadFile = &::mrk::remote_detail::ReadFile;
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
