#include "alloc.h"

namespace mrk {

	////////////////////////////////////////////////////////////////////////////////////////////////////
	// RemoteBuffer
	////////////////////////////////////////////////////////////////////////////////////////////////////

	RemoteBuffer::RemoteBuffer(HANDLE hProc, size_t size, void* localAddr)
		: hProc_(hProc), remoteAddr_(nullptr), size_(size), localAddr_(localAddr) {
		if (hProc && size > 0) {
			VLOG("Allocating %sremote buffer (%zu bytes)", localAddr ? "READ BACK " : "", size);

			remoteAddr_ = VirtualAllocEx(hProc, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if (remoteAddr_) {
				// Zero-initialize the buffer
				std::vector<uint8_t> zeros(size, 0);
				WriteProcessMemory(hProc, remoteAddr_, zeros.data(), size, nullptr);
				VLOG("Remote buffer allocated at: %p", remoteAddr_);

				// Zero-initialize local buffer
				if (localAddr_) {
					ZeroMemory(localAddr_, size_);
				}
			}
			else {
				VLOG("Failed to allocate remote buffer. Error: %lu", GetLastError());
			}
		}
	}

	RemoteBuffer::RemoteBuffer(HANDLE hProc, const char* str)
		: hProc_(hProc), remoteAddr_(nullptr), size_(0) {
		if (str && hProc) {
			size_ = strlen(str) + 1;

			VLOG("Allocating remote string (ANSI): \"%s\" (%zu bytes)", str, size_);

			remoteAddr_ = VirtualAllocEx(hProc, nullptr, size_, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if (remoteAddr_) {
				WriteProcessMemory(hProc, remoteAddr_, str, size_, nullptr);
				VLOG("Remote string allocated at: %p", remoteAddr_);
			}
			else {
				VLOG("Failed to allocate remote string. Error: %lu", GetLastError());
			}
		}
	}

	RemoteBuffer::RemoteBuffer(HANDLE hProc, const wchar_t* str)
		: hProc_(hProc), remoteAddr_(nullptr), size_(0) {
		if (str && hProc) {
			size_ = (wcslen(str) + 1) * sizeof(wchar_t);

			VLOG("Allocating remote wstring: \"%ws\" (%zu bytes)", str, size_);

			remoteAddr_ = VirtualAllocEx(hProc, nullptr, size_, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if (remoteAddr_) {
				WriteProcessMemory(hProc, remoteAddr_, str, size_, nullptr);
				VLOG("Remote string allocated at: %p", remoteAddr_);
			}
			else {
				VLOG("Failed to allocate remote string. Error: %lu", GetLastError());
			}
		}
	}

	RemoteBuffer::~RemoteBuffer() {
		// Read back if needed
		if (localAddr_ && isValid()) {
			read(localAddr_, size_);
		}

		free();
	}

	RemoteBuffer::RemoteBuffer(RemoteBuffer&& other) noexcept
		: hProc_(other.hProc_), remoteAddr_(other.remoteAddr_), size_(other.size_), localAddr_(other.localAddr_) {
		other.remoteAddr_ = nullptr;
		other.size_ = 0;
	}

	RemoteBuffer& RemoteBuffer::operator=(RemoteBuffer&& other) noexcept {
		if (this != &other) {
			free();
			hProc_ = other.hProc_;
			remoteAddr_ = other.remoteAddr_;
			size_ = other.size_;
			localAddr_ = other.localAddr_;

			other.remoteAddr_ = nullptr;
			other.size_ = 0;
		}

		return *this;
	}

	void RemoteBuffer::free() {
		if (remoteAddr_ && hProc_) {
			VLOG("Freeing remote buffer at: %p (%zu bytes)", remoteAddr_, size_);
			VirtualFreeEx(hProc_, remoteAddr_, 0, MEM_RELEASE);
			remoteAddr_ = nullptr;
		}
	}

	bool RemoteBuffer::read(void* dest, size_t readSize) const {
		if (!remoteAddr_ || !dest) return false;
		if (readSize == 0) readSize = size_;
		if (readSize > size_) readSize = size_;

		VLOG("Reading back remote buffer (%zu bytes) to local address: %p", size_, localAddr_);
		return ReadProcessMemory(hProc_, remoteAddr_, dest, readSize, nullptr) != FALSE;
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	// RemoteAllocationManager
	////////////////////////////////////////////////////////////////////////////////////////////////////

	RemoteAllocationManager::RemoteAllocationManager(HANDLE hProc)
		: hProc_(hProc) {
		VLOG("RemoteAllocationManager created for process: %p", hProc);
	}

	RemoteAllocationManager::~RemoteAllocationManager() {
		cleanup();
	}

	void RemoteAllocationManager::cleanup() {
		if (!allocations_.empty()) {
			VLOG("RemoteAllocationManager: Cleaning up %zu allocations", allocations_.size());
			allocations_.clear();
		}
	}

} // namespace mrk