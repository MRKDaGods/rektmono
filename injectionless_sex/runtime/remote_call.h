#pragma once

#include "../logger.h"
#include "remote_args.h"
#include "remote_string.h"

#include <Windows.h>
#include <type_traits>

namespace mrk {
	namespace detail {
		// Type traits to detect string types
		template<typename T>
		struct is_string : std::false_type {};
		
		template<> struct is_string<const char*> : std::true_type {};
		template<> struct is_string<char*> : std::true_type {};
		template<size_t N> struct is_string<const char[N]> : std::true_type {};
		template<size_t N> struct is_string<char[N]> : std::true_type {};
		template<> struct is_string<const wchar_t*> : std::true_type {};
		template<> struct is_string<wchar_t*> : std::true_type {};
		template<size_t N> struct is_string<const wchar_t[N]> : std::true_type {};
		template<size_t N> struct is_string<wchar_t[N]> : std::true_type {};

		// Helper to process arguments: allocate strings and buffers, pass through everything else
		template<typename T>
		inline auto processArg(HANDLE hProc, RemoteStringManager& stringMgr, T&& arg) {
			if constexpr (std::is_same_v<std::decay_t<T>, RemoteBufferRequest>) {
				// Allocate buffer in remote process
				VLOG("Processing RemoteBufferRequest for automatic buffer allocation (%zu bytes)", arg.size);
				return stringMgr.allocate(arg);
			} else if constexpr (is_string<std::decay_t<T>>::value) {
				// Allocate string in remote process
				VLOG("Processing string argument for remote allocation");
				return stringMgr.allocate(arg);
			} else {
				// Pass through
				VLOG("Processing non-string argument (pass-through): 0x%p", (void*)arg);
				return std::forward<T>(arg);
			}
		}
	}

	// Forward declaration
	bool executeRemoteFunction(HANDLE hProc, HANDLE hThread, RemoteFunction function, RemoteFunctionArgs& args, 
		PDWORD result, size_t estimatedFunctionSize);

	template<typename... Args>
	inline bool callRemoteFunction(HANDLE hProc, HANDLE hThread, RemoteFunction function, Args&&... args) {
		VLOG("callRemoteFunction: Starting with %zu arguments", sizeof...(Args));
		
		// Create string manager for automatic cleanup
		RemoteStringManager stringMgr(hProc);

		// Process arguments
		RemoteFunctionArgs funcArgs = packRemoteArgs(detail::processArg(hProc, stringMgr, std::forward<Args>(args))...);
		
		VLOG("callRemoteFunction: Arguments packed, executing remote function");
		
		// Execute the function
		return executeRemoteFunction(hProc, hThread, function, funcArgs, nullptr, static_cast<size_t>(-1));
	}

	// Overload with result capture
	template<typename... Args>
	inline bool callRemoteFunction(HANDLE hProc, HANDLE hThread, RemoteFunction function, PDWORD result, Args&&... args) {
		VLOG("callRemoteFunction: Starting with %zu arguments (with result capture)", sizeof...(Args));
		
		RemoteStringManager stringMgr(hProc);
		RemoteFunctionArgs funcArgs = packRemoteArgs(detail::processArg(hProc, stringMgr, std::forward<Args>(args))...);
		
		VLOG("callRemoteFunction: Arguments packed, executing remote function");
		
		return executeRemoteFunction(hProc, hThread, function, funcArgs, result, static_cast<size_t>(-1));
	}
}
