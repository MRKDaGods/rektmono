#pragma once

#include "remote_args.h"

#include <Windows.h>
#include <type_traits>

namespace mrk {
	// Forward declaration
	bool executeRemoteFunction(HANDLE hProc, HANDLE hThread, RemoteFunction function, RemoteFunctionArgs& args, 
		PDWORD result, size_t estimatedFunctionSize);
	
	// 4-argument API call
	template<typename RetType, typename A1, typename A2, typename A3, typename A4>
	struct RemoteApiCall4 {
		using FuncPtr = RetType(WINAPI*)(A1, A2, A3, A4);
		
		static DWORD __stdcall Invoke(RemoteFunctionArgs* args) {
			auto funcPtr = reinterpret_cast<FuncPtr>(args->args[0]);
			return static_cast<DWORD>(funcPtr(
				reinterpret_cast<A1>(args->args[1]),
				reinterpret_cast<A2>(args->args[2]),
				reinterpret_cast<A3>(args->args[3]),
				static_cast<A4>(args->args[4])
			));
		}
	};

	// 3-argument API call
	template<typename RetType, typename A1, typename A2, typename A3>
	struct RemoteApiCall3 {
		using FuncPtr = RetType(WINAPI*)(A1, A2, A3);
		
		static DWORD __stdcall Invoke(RemoteFunctionArgs* args) {
			auto funcPtr = reinterpret_cast<FuncPtr>(args->args[0]);
			return static_cast<DWORD>(funcPtr(
				reinterpret_cast<A1>(args->args[1]),
				reinterpret_cast<A2>(args->args[2]),
				static_cast<A3>(args->args[3])
			));
		}
	};

	// 2-argument API call
	template<typename RetType, typename A1, typename A2>
	struct RemoteApiCall2 {
		using FuncPtr = RetType(WINAPI*)(A1, A2);
		
		static DWORD __stdcall Invoke(RemoteFunctionArgs* args) {
			auto funcPtr = reinterpret_cast<FuncPtr>(args->args[0]);
			return static_cast<DWORD>(funcPtr(
				reinterpret_cast<A1>(args->args[1]),
				static_cast<A2>(args->args[2])
			));
		}
	};

	// 1-argument API call
	template<typename RetType, typename A1>
	struct RemoteApiCall1 {
		using FuncPtr = RetType(WINAPI*)(A1);
		
		static DWORD __stdcall Invoke(RemoteFunctionArgs* args) {
			auto funcPtr = reinterpret_cast<FuncPtr>(args->args[0]);
			if constexpr (std::is_void_v<RetType>) {
				funcPtr(static_cast<A1>(args->args[1]));
				return 0;
			} else {
				return static_cast<DWORD>(funcPtr(static_cast<A1>(args->args[1])));
			}
		}
	};

	// Helper functions for calling Windows APIs remotely
	
	// Call a 4-argument Windows API without capturing result
	template<typename RetType, typename A1, typename A2, typename A3, typename A4>
	inline bool callRemoteApi(HANDLE hProc, HANDLE hThread, 
		RetType(WINAPI* func)(A1, A2, A3, A4), A1 a1, A2 a2, A3 a3, A4 a4) {
		RemoteFunctionArgs args{};
		args.args[0] = reinterpret_cast<uintptr_t>(func);
		args.args[1] = detail::toUintPtr(a1);
		args.args[2] = detail::toUintPtr(a2);
		args.args[3] = detail::toUintPtr(a3);
		args.args[4] = detail::toUintPtr(a4);
		
		DWORD result = 0;
		return executeRemoteFunction(hProc, hThread, 
			RemoteApiCall4<RetType, A1, A2, A3, A4>::Invoke, args, &result, static_cast<size_t>(-1));
	}

	// Call a 4-argument Windows API with result capture
	template<typename RetType, typename A1, typename A2, typename A3, typename A4>
	inline bool callRemoteApi(HANDLE hProc, HANDLE hThread, 
		RetType(WINAPI* func)(A1, A2, A3, A4), A1 a1, A2 a2, A3 a3, A4 a4, RetType* outResult) {
		RemoteFunctionArgs args{};
		args.args[0] = reinterpret_cast<uintptr_t>(func);
		args.args[1] = detail::toUintPtr(a1);
		args.args[2] = detail::toUintPtr(a2);
		args.args[3] = detail::toUintPtr(a3);
		args.args[4] = detail::toUintPtr(a4);
		
		DWORD result = 0;
		bool success = executeRemoteFunction(hProc, hThread, 
			RemoteApiCall4<RetType, A1, A2, A3, A4>::Invoke, args, &result, static_cast<size_t>(-1));
		
		if (success && outResult) {
			*outResult = static_cast<RetType>(result);
		}
		return success;
	}

	// Call a 3-argument Windows API
	template<typename RetType, typename A1, typename A2, typename A3>
	inline bool callRemoteApi(HANDLE hProc, HANDLE hThread, 
		RetType(WINAPI* func)(A1, A2, A3), A1 a1, A2 a2, A3 a3, RetType* outResult = nullptr) {
		RemoteFunctionArgs args{};
		args.args[0] = reinterpret_cast<uintptr_t>(func);
		args.args[1] = detail::toUintPtr(a1);
		args.args[2] = detail::toUintPtr(a2);
		args.args[3] = detail::toUintPtr(a3);
		
		DWORD result = 0;
		bool success = executeRemoteFunction(hProc, hThread, 
			RemoteApiCall3<RetType, A1, A2, A3>::Invoke, args, &result, static_cast<size_t>(-1));
		
		if (success && outResult) {
			*outResult = static_cast<RetType>(result);
		}
		return success;
	}

	// Call a 2-argument Windows API
	template<typename RetType, typename A1, typename A2>
	inline bool callRemoteApi(HANDLE hProc, HANDLE hThread, 
		RetType(WINAPI* func)(A1, A2), A1 a1, A2 a2, RetType* outResult = nullptr) {
		RemoteFunctionArgs args{};
		args.args[0] = reinterpret_cast<uintptr_t>(func);
		args.args[1] = detail::toUintPtr(a1);
		args.args[2] = detail::toUintPtr(a2);
		
		DWORD result = 0;
		bool success = executeRemoteFunction(hProc, hThread, 
			RemoteApiCall2<RetType, A1, A2>::Invoke, args, &result, static_cast<size_t>(-1));
		
		if (success && outResult) {
			*outResult = static_cast<RetType>(result);
		}
		return success;
	}

	// Call a 1-argument Windows API
	template<typename RetType, typename A1>
	inline bool callRemoteApi(HANDLE hProc, HANDLE hThread, 
		RetType(WINAPI* func)(A1), A1 a1, RetType* outResult = nullptr) {
		RemoteFunctionArgs args{};
		args.args[0] = reinterpret_cast<uintptr_t>(func);
		args.args[1] = detail::toUintPtr(a1);
		
		DWORD result = 0;
		bool success = executeRemoteFunction(hProc, hThread, 
			RemoteApiCall1<RetType, A1>::Invoke, args, &result, static_cast<size_t>(-1));
		
		if constexpr (!std::is_void_v<RetType>) {
			if (success && outResult) {
				*outResult = static_cast<RetType>(result);
			}
		}
		return success;
	}
}
