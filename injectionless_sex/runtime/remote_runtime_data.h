// Remote execution runtime utilities and declarations
// Ammar by7ebko ;)

#pragma once

#include <Windows.h>
#include <Psapi.h>

#define DECLARE_API_FUNC(funcname) decltype(&funcname) funcname = &::funcname

namespace mrk {

	struct WinAPI {
		DECLARE_API_FUNC(LoadLibraryA);
		DECLARE_API_FUNC(GetProcAddress);
		DECLARE_API_FUNC(K32GetModuleInformation);
		DECLARE_API_FUNC(GetCurrentProcess);
		DECLARE_API_FUNC(MessageBoxA);
		DECLARE_API_FUNC(wsprintfA);
	};

	struct MRKAPI {
		/// Currently invalid in remote process
		/// Use winapi.GetCurrentProcess()
		HANDLE hProc; 
	};

	struct RemoteRuntimeData {
		WinAPI winapi;
		MRKAPI mrkapi;

		/// For use by printf, etc
		/// We can also use mrk::stackalloc(xxx) for dynamic allocation of buffers
		char buffer[256];
	};

}