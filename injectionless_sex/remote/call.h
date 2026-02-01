#pragma once

#include "../logger.h"
#include "../utils/traits.h"
#include "runtime.h"
#include "args.h"
#include "alloc.h"

#include <Windows.h>
#include <type_traits>

namespace mrk {
	namespace detail {

		/// Helper to process arguments: allocate strings and buffers, pass through everything else
		template<typename T>
		inline auto processArg(RemoteAllocationManager& allocMgr, T&& arg) {
			if constexpr (std::is_same_v<std::decay_t<T>, RemoteBufferRequest>) {
				// Allocate buffer in remote process
				VLOG("Processing RemoteBufferRequest for automatic buffer allocation (%zu bytes)", arg.size);
				return allocMgr.allocate(arg);
			} else if constexpr (traits::is_string_v<std::decay_t<T>>) {
				// Allocate string in remote process
				VLOG("Processing string argument for remote allocation");
				return allocMgr.allocate(arg);
			} else {
				// Pass through
				VLOG("Processing non-string argument (pass-through): 0x%p", (void*)arg);
				return std::forward<T>(arg);
			}
		}
	}

	template<typename... Args>
	inline bool callRemoteFunction(HANDLE hProc, HANDLE hThread, const void* runtimeDataAddr, RemoteFunction function, Args&&... args) {
		VLOG("callRemoteFunction: Starting with %zu arguments", sizeof...(Args));
		
		// Create string manager for automatic cleanup
		RemoteAllocationManager allocMgr(hProc);

		// Process arguments
		RemoteFunctionArgs funcArgs = packRemoteArgs(runtimeDataAddr, detail::processArg(allocMgr, std::forward<Args>(args))...);

		VLOG("callRemoteFunction: Arguments packed, executing remote function");
		return executeRemoteFunction(hProc, hThread, function, funcArgs, nullptr, static_cast<size_t>(-1));
	}

	/// Overload with result capture
	template<typename... Args>
	inline bool callRemoteFunction(HANDLE hProc, HANDLE hThread, const void* runtimeDataAddr, RemoteFunction function, PDWORD result, Args&&... args) {
		VLOG("callRemoteFunction: Starting with %zu arguments (with result capture)", sizeof...(Args));
		
		// Initialially zero out result
		if (result) {
			*result = static_cast<DWORD>(-1);
		}

		RemoteAllocationManager allocMgr(hProc);
		RemoteFunctionArgs funcArgs = packRemoteArgs(runtimeDataAddr, detail::processArg(allocMgr, std::forward<Args>(args))...);

		VLOG("callRemoteFunction: Arguments packed, executing remote function (result capture)");
		return executeRemoteFunction(hProc, hThread, function, funcArgs, result, static_cast<size_t>(-1));
	}
}
