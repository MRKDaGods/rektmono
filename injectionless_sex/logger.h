#pragma once

#define DISABLE_VERBOSE_LOGGING

#ifndef DISABLE_LOGGING
#include <cstdio>
#define LOG(msg, ...) printf("[m] " msg "\n", ##__VA_ARGS__)
#else
#define LOG(msg, ...)
#endif

#ifndef DISABLE_VERBOSE_LOGGING
#include <cstdio>
#define VLOG(msg, ...) printf("[v] " msg "\n", ##__VA_ARGS__)
#else
#define VLOG(msg, ...)
#endif

#include <type_traits>

namespace mrk {
	namespace detail {
		// Print upto 8 arrs per LOG
		constexpr auto BUFFER_COUNT = 8;
		constexpr auto BUFFER_SZ = 512;

		typedef char BUFFER[BUFFER_SZ];
		inline thread_local BUFFER buffers[BUFFER_COUNT];
		inline thread_local size_t curBufferIdx = 0;

		inline char* getBuffer() {
			char* buf = buffers[curBufferIdx];
			curBufferIdx = (curBufferIdx + 1) % BUFFER_COUNT;
			return buf;
		}

		template<typename T>
		constexpr const char* getFormatStr() {
			if constexpr (std::is_same_v<T, char> || std::is_same_v<T, signed char>) {
				return "%c";
			}
			else if constexpr (std::is_same_v<T, unsigned char> || std::is_same_v<T, uint8_t>) {
				return "0x%02X";
			}
			else if constexpr (std::is_same_v<T, short>) {
				return "%hd";
			}
			else if constexpr (std::is_same_v<T, unsigned short> || std::is_same_v<T, uint16_t>) {
				return "0x%04X";
			}
			else if constexpr (std::is_same_v<T, int> || std::is_same_v<T, int32_t>) {
				return "%d";
			}
			else if constexpr (std::is_same_v<T, unsigned int> || std::is_same_v<T, uint32_t>) {
				return "0x%08X";
			}
			else if constexpr (std::is_same_v<T, long long> || std::is_same_v<T, int64_t>) {
				return "%lld";
			}
			else if constexpr (std::is_same_v<T, unsigned long long> || std::is_same_v<T, uint64_t>) {
				return "0x%016llX";
			}
			else if constexpr (std::is_same_v<T, float>) {
				return "%.2f";
			}
			else if constexpr (std::is_same_v<T, double>) {
				return "%.4f";
			}
			else if constexpr (std::is_pointer_v<T>) {
				return "0x%p";
			}
			else {
				return "%d";  // Fallback
			}
		}
	}

	template<typename T>
	inline const char* ARR(const T* arr, size_t count) {
		char* buf = detail::getBuffer();
		size_t offset = 0;

		for (size_t i = 0; i < count && offset < detail::BUFFER_SZ - 10; i++) {
			if (i > 0) {
				buf[offset++] = ' ';
			}

			// Promote types smaller than int for integral types
			using Ty = std::conditional_t<
				std::is_integral_v<T> && sizeof(T) < sizeof(int),
				std::conditional_t<std::is_unsigned_v<T>, unsigned int, int>,
				T
			>;

			int written = snprintf(buf + offset, detail::BUFFER_SZ - offset, 
								   detail::getFormatStr<T>(), static_cast<Ty>(arr[i]));

			if (written > 0 && static_cast<size_t>(written) < detail::BUFFER_SZ - offset) {
				offset += static_cast<size_t>(written);
			}
			else {
				break;
			}
		}

		buf[offset] = '\0';
		return buf;
	}

	template<typename T, size_t N>
	inline const char* ARR(const T(&arr)[N]) {
		return ARR(arr, N);
	}
}