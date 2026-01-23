#pragma once

#include <Windows.h>
#include <cstdint>

// Placeholder address for embedded runtime data
#define EMBEDDED_RUNTIME_DATA_PLACEHOLDER 0xD1EAF1F1EE50AA67ULL

namespace mrk {
	/// Forward declaration
	struct RemoteRuntimeData;

	/// Structure to hold remote function arguments
	struct RemoteFunctionArgs {
		uintptr_t args[16]; // eshm3na 16?
	};

	/// Remote function signature
	typedef DWORD(__stdcall* RemoteFunction)(RemoteFunctionArgs* args);

	/// Helper function to generate movabs rax, EMBEDDED_RUNTIME_DATA_PLACEHOLDER
	__forceinline RemoteRuntimeData* __getRuntimeDataPtr() {
		// movabs rax, 0D1EAF1F1EE50AA67h
		return reinterpret_cast<RemoteRuntimeData*>(
			static_cast<uintptr_t>(EMBEDDED_RUNTIME_DATA_PLACEHOLDER));
	}
}

// Macros for defining and accessing remote function arguments
#define REMOTE_FUNCTION(...) \
		static DWORD __stdcall __VA_ARGS__(mrk::RemoteFunctionArgs* __args__)

#define REMOTE_ARG(index, type) reinterpret_cast<type>(__args__->args[index])
#define REMOTE_RUNTIME_DATA_ARG() REMOTE_ARG(0, struct mrk::RemoteRuntimeData*)

// For hooked functions that need embedded runtime data
// The runtime data address will be patched into the function by allocatePersistentRemoteFunction
#define REMOTE_HOOKED_FUNCTION(name, ...) \
		static DWORD __stdcall name(__VA_ARGS__)

// Macro to access the embedded runtime data in hooked functions
#define REMOTE_HOOKED_RUNTIME_DATA() mrk::__getRuntimeDataPtr()

namespace mrk {
	namespace detail {
		template<typename T>
		inline uintptr_t toUintPtr(T* value) {
			return reinterpret_cast<uintptr_t>(value);
		}

		inline uintptr_t toUintPtr(int value) {
			return static_cast<uintptr_t>(value);
		}

		inline uintptr_t toUintPtr(unsigned int value) {
			return static_cast<uintptr_t>(value);
		}

		inline uintptr_t toUintPtr(long value) {
			return static_cast<uintptr_t>(value);
		}

		inline uintptr_t toUintPtr(unsigned long value) {
			return static_cast<uintptr_t>(value);
		}

		inline uintptr_t toUintPtr(long long value) {
			return static_cast<uintptr_t>(value);
		}

		inline uintptr_t toUintPtr(unsigned long long value) {
			return static_cast<uintptr_t>(value);
		}

		template<size_t Index>
		inline void packArgs(RemoteFunctionArgs& /*args*/) {
			// Base case: no more arguments
		}

		template<size_t Index, typename T, typename... Rest>
		inline void packArgs(RemoteFunctionArgs& args, T first, Rest... rest) {
			static_assert(Index < 16, "Too many arguments (max 16)");
			args.args[Index] = toUintPtr(first);
			packArgs<Index + 1>(args, rest...);
		}
	}

	/// Helper for packing arguments manually
	template<typename... Args>
	inline RemoteFunctionArgs packRemoteArgs(const void* runtimeDataAddr, Args... args) {
		RemoteFunctionArgs result{};

		// Keep at 0
		detail::packArgs<0>(result, runtimeDataAddr);

		// Pack remaining arguments
		detail::packArgs<1>(result, args...);
		return result;
	}
}
