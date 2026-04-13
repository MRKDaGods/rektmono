#pragma once

#include "../logger.h"
#include "../utils/traits.h"

#include <Windows.h>
#include <vector>

namespace mrk {

	/// Special marker type for requesting automatic buffer allocation
	/// As well as objects...
	/// 
	/// E.g: MODULEINFO* mi = stackalloc(sizeof(MODULEINFO));
	struct RemoteBufferRequest {
		size_t size;
		void* localAddr; // If valid, the buffer will be read back after the call

		constexpr explicit RemoteBufferRequest(size_t sz, void* localAddr = nullptr) 
			: size(sz), localAddr(localAddr) {}
	};

	namespace remote {

		/// Helper function to create buffer requests
		constexpr RemoteBufferRequest stackalloc(size_t size) {
			return RemoteBufferRequest(size);
		}

		template<typename T>
		constexpr RemoteBufferRequest stackalloc() {
			return RemoteBufferRequest(sizeof(T));
		}

		/// Output buffer request - indicates that the buffer will be read back after the call
		template<typename T>
		constexpr RemoteBufferRequest out(T* localAddr) {
			return RemoteBufferRequest(sizeof(T), localAddr);
		}

	} // namespace remote

	/// Helper class for managing a writable buffer in remote process with RAII
	class RemoteBuffer {
	public:
		RemoteBuffer() : hProc_(nullptr), remoteAddr_(nullptr), size_(0), localAddr_(nullptr) {}

		/// Zerod out remote buffer ctor
		RemoteBuffer(HANDLE hProc, size_t size, void* localAddr);

		// String ctors
		RemoteBuffer(HANDLE hProc, const char* str);
		RemoteBuffer(HANDLE hProc, const wchar_t* str);

		~RemoteBuffer();

		// Move semantics
		RemoteBuffer(RemoteBuffer&& other) noexcept;
		RemoteBuffer& operator=(RemoteBuffer&& other) noexcept;

		// Delete copy semantics
		RemoteBuffer(const RemoteBuffer&) = delete;
		RemoteBuffer& operator=(const RemoteBuffer&) = delete;

		/// Read data back from the remote buffer
		bool read(void* dest, size_t readSize = 0) const;

		void* address() const { return remoteAddr_; }
		uintptr_t uintptr() const { return reinterpret_cast<uintptr_t>(remoteAddr_); }
		bool isValid() const { return remoteAddr_ != nullptr; }
		size_t size() const { return size_; }

	private:
		void free();

		HANDLE hProc_;
		void* remoteAddr_;
		size_t size_;
		void* localAddr_;
	};

	/// Manager for multiple remote strings and buffers with automatic cleanup
	class RemoteAllocationManager {
	public:
		RemoteAllocationManager(HANDLE hProc);
		~RemoteAllocationManager();

		template<typename T>
		inline void* allocate(T data) {
			RemoteBuffer buf;
			if constexpr (std::is_same_v<std::decay_t<T>, RemoteBufferRequest>) {
				buf = RemoteBuffer(hProc_, data.size, data.localAddr);
			}
			else if constexpr (traits::is_string_v<std::decay_t<T>>) {
				buf = RemoteBuffer(hProc_, data);
			}

			if (!buf.isValid()) return nullptr;

			auto addr = buf.address();
			allocations_.push_back(std::move(buf));
			VLOG("RemoteAllocationManager: Tracking %zu buffers", allocations_.size());
			return addr;
		}

	private:
		void cleanup();

		HANDLE hProc_;
		std::vector<RemoteBuffer> allocations_;
	};

} // namespace mrk
