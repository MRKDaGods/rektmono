#pragma once

#include <Windows.h>
#include <cstdint>

namespace mrk {
	// Structure to hold remote function arguments
	struct RemoteFunctionArgs {
		uintptr_t args[16];
	};

	// Remote function signature
	typedef DWORD(__stdcall* RemoteFunction)(RemoteFunctionArgs* args);

	// Macros for defining and accessing remote function arguments
	#define REMOTE_FUNCTION(...) \
		static DWORD __stdcall __VA_ARGS__(mrk::RemoteFunctionArgs* __args__)

	#define REMOTE_ARG(index, type) reinterpret_cast<type>(__args__->args[index])

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

	// Helper for packing arguments manually
	template<typename... Args>
	inline RemoteFunctionArgs packRemoteArgs(Args... args) {
		RemoteFunctionArgs result{};
		detail::packArgs<0>(result, args...);
		return result;
	}
}
