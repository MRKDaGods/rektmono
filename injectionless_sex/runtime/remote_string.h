#pragma once

#include "../logger.h"

#include <Windows.h>
#include <vector>

namespace mrk {
	// Special marker type for requesting automatic buffer allocation
	struct RemoteBufferRequest {
		size_t size;
		constexpr explicit RemoteBufferRequest(size_t sz) : size(sz) {}
	};

	// Helper function to create buffer requests
	constexpr RemoteBufferRequest remoteBuffer(size_t size) {
		return RemoteBufferRequest(size);
	}

	// Helper class for managing a single string in remote process with RAII
	class RemoteString {
	public:
		RemoteString() : hProc_(nullptr), remoteAddr_(nullptr), size_(0) {}
		
		RemoteString(HANDLE hProc, const char* str) : hProc_(hProc), remoteAddr_(nullptr), size_(0) {
			if (str && hProc) {
				size_ = strlen(str) + 1;
				VLOG("Allocating remote string (ANSI): \"%s\" (%zu bytes)", str, size_);
				remoteAddr_ = VirtualAllocEx(hProc, nullptr, size_, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
				if (remoteAddr_) {
					WriteProcessMemory(hProc, remoteAddr_, str, size_, nullptr);
					VLOG("Remote string allocated at: %p", remoteAddr_);
				} else {
					VLOG("Failed to allocate remote string. Error: %lu", GetLastError());
				}
			}
		}

		RemoteString(HANDLE hProc, const wchar_t* str) : hProc_(hProc), remoteAddr_(nullptr), size_(0) {
			if (str && hProc) {
				size_ = (wcslen(str) + 1) * sizeof(wchar_t);
				VLOG("Allocating remote string (UNICODE): \"%ws\" (%zu bytes)", str, size_);
				remoteAddr_ = VirtualAllocEx(hProc, nullptr, size_, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
				if (remoteAddr_) {
					WriteProcessMemory(hProc, remoteAddr_, str, size_, nullptr);
					VLOG("Remote string allocated at: %p", remoteAddr_);
				} else {
					VLOG("Failed to allocate remote string. Error: %lu", GetLastError());
				}
			}
		}

		~RemoteString() {
			free();
		}

		// Move semantics
		RemoteString(RemoteString&& other) noexcept 
			: hProc_(other.hProc_), remoteAddr_(other.remoteAddr_), size_(other.size_) {
			other.remoteAddr_ = nullptr;
			other.size_ = 0;
		}

		RemoteString& operator=(RemoteString&& other) noexcept {
			if (this != &other) {
				free();
				hProc_ = other.hProc_;
				remoteAddr_ = other.remoteAddr_;
				size_ = other.size_;
				other.remoteAddr_ = nullptr;
				other.size_ = 0;
			}

			return *this;
		}

		// Delete copy semantics
		RemoteString(const RemoteString&) = delete;
		RemoteString& operator=(const RemoteString&) = delete;

		void free() {
			if (remoteAddr_ && hProc_) {
				VLOG("Freeing remote string at: %p (%zu bytes)", remoteAddr_, size_);
				VirtualFreeEx(hProc_, remoteAddr_, 0, MEM_RELEASE);
				remoteAddr_ = nullptr;
			}
		}

		void* address() const { return remoteAddr_; }
		uintptr_t uintptr() const { return reinterpret_cast<uintptr_t>(remoteAddr_); }
		bool isValid() const { return remoteAddr_ != nullptr; }

	private:
		HANDLE hProc_;
		void* remoteAddr_;
		size_t size_;
	};

	// Helper class for managing a writable buffer in remote process with RAII
	class RemoteBuffer {
	public:
		RemoteBuffer() : hProc_(nullptr), remoteAddr_(nullptr), size_(0) {}
		
		RemoteBuffer(HANDLE hProc, size_t size) : hProc_(hProc), remoteAddr_(nullptr), size_(size) {
			if (hProc && size > 0) {
				VLOG("Allocating remote buffer (%zu bytes)", size);
				remoteAddr_ = VirtualAllocEx(hProc, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
				if (remoteAddr_) {
					// Zero-initialize the buffer
					std::vector<uint8_t> zeros(size, 0);
					WriteProcessMemory(hProc, remoteAddr_, zeros.data(), size, nullptr);
					VLOG("Remote buffer allocated at: %p", remoteAddr_);
				} else {
					VLOG("Failed to allocate remote buffer. Error: %lu", GetLastError());
				}
			}
		}

		~RemoteBuffer() {
			free();
		}

		// Move semantics
		RemoteBuffer(RemoteBuffer&& other) noexcept 
			: hProc_(other.hProc_), remoteAddr_(other.remoteAddr_), size_(other.size_) {
			other.remoteAddr_ = nullptr;
			other.size_ = 0;
		}

		RemoteBuffer& operator=(RemoteBuffer&& other) noexcept {
			if (this != &other) {
				free();
				hProc_ = other.hProc_;
				remoteAddr_ = other.remoteAddr_;
				size_ = other.size_;
				other.remoteAddr_ = nullptr;
				other.size_ = 0;
			}
			return *this;
		}

		// Delete copy semantics
		RemoteBuffer(const RemoteBuffer&) = delete;
		RemoteBuffer& operator=(const RemoteBuffer&) = delete;

		void free() {
			if (remoteAddr_ && hProc_) {
				VLOG("Freeing remote buffer at: %p (%zu bytes)", remoteAddr_, size_);
				VirtualFreeEx(hProc_, remoteAddr_, 0, MEM_RELEASE);
				remoteAddr_ = nullptr;
			}
		}

		// Read data back from the remote buffer
		// TODO: Conditional buffer freeing, so that we can read data back from it
		bool read(void* dest, size_t readSize = 0) const {
			if (!remoteAddr_ || !dest) return false;
			if (readSize == 0) readSize = size_;
			if (readSize > size_) readSize = size_;
			
			return ReadProcessMemory(hProc_, remoteAddr_, dest, readSize, nullptr) != FALSE;
		}

		void* address() const { return remoteAddr_; }
		uintptr_t uintptr() const { return reinterpret_cast<uintptr_t>(remoteAddr_); }
		bool isValid() const { return remoteAddr_ != nullptr; }
		size_t size() const { return size_; }

	private:
		HANDLE hProc_;
		void* remoteAddr_;
		size_t size_;
	};

	// Manager for multiple remote strings and buffers with automatic cleanup
	class RemoteStringManager {
	public:
		RemoteStringManager(HANDLE hProc) : hProc_(hProc) {
			VLOG("RemoteStringManager created for process: %p", hProc);
		}

		~RemoteStringManager() {
			cleanup();
		}

		// Allocate a string in remote process and track it
		const char* allocate(const char* str) {
			if (!str) return nullptr;
			
			RemoteString remoteStr(hProc_, str);
			if (!remoteStr.isValid()) return nullptr;
			
			auto addr = reinterpret_cast<const char*>(remoteStr.address());
			strings_.push_back(std::move(remoteStr));
			VLOG("RemoteStringManager: Tracking %zu strings", strings_.size());
			return addr;
		}

		const wchar_t* allocate(const wchar_t* str) {
			if (!str) return nullptr;
			
			RemoteString remoteStr(hProc_, str);
			if (!remoteStr.isValid()) return nullptr;
			
			auto addr = reinterpret_cast<const wchar_t*>(remoteStr.address());
			strings_.push_back(std::move(remoteStr));
			VLOG("RemoteStringManager: Tracking %zu strings", strings_.size());
			return addr;
		}

		// Allocate a buffer in remote process and track it
		void* allocate(RemoteBufferRequest request) {
			RemoteBuffer remoteBuffer(hProc_, request.size);
			if (!remoteBuffer.isValid()) return nullptr;
			
			auto addr = remoteBuffer.address();
			buffers_.push_back(std::move(remoteBuffer));
			VLOG("RemoteStringManager: Tracking %zu buffers", buffers_.size());
			return addr;
		}

		// Clean up all allocated strings and buffers
		void cleanup() {
			if (!strings_.empty()) {
				VLOG("RemoteStringManager: Cleaning up %zu strings", strings_.size());
				strings_.clear(); // Destructors will free memory
			}

			if (!buffers_.empty()) {
				VLOG("RemoteStringManager: Cleaning up %zu buffers", buffers_.size());
				buffers_.clear(); // Destructors will free memory
			}
		}

	private:
		HANDLE hProc_;
		std::vector<RemoteString> strings_;
		std::vector<RemoteBuffer> buffers_;
	};
}
