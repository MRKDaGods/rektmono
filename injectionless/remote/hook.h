#pragma once

// Happy new year 2026

#include "../logger.h"

#include <Windows.h>
#include <cstdint>

namespace mrk {

	// Hook ctx somewhere
	// Tramp here and there
	// Bas kda

	struct RemoteHookContext {
		struct {
			size_t originalBytesSz;
			uint8_t* originalBytes;

			// Local copy of trampoline
			// Used during construction
			void* trampoline;
		} local; // Accessed via local ctx

		struct {
			size_t trampolineSz;
			void* trampoline;
		} remote; // ... remote ctx
	};

	bool remoteHook(HANDLE hProc, void* srcFunction, void* targetFunction, RemoteHookContext* outCtx);

}