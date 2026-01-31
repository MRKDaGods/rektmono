#include "utils.h"
#include "nmd_assembly.h"
#include "../logger.h"

#include <vector>

namespace mrk {

	bool isPageReadable(PMEMORY_BASIC_INFORMATION mbi) {
		if ((mbi->State & MEM_COMMIT) != MEM_COMMIT) {
			return false;
		}

		if (mbi->Protect & (PAGE_GUARD | PAGE_NOACCESS)) {
			return false;
		}

		return mbi->Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE);
	}

	/// Gets the image base of the module containing addr
	void* getImageBase(void* addr, bool searchForward = true) {
		uintptr_t base = reinterpret_cast<uintptr_t>(addr) & ~0xFFFFF;
		for (unsigned i = 0; i < 0x100000; i += 0x10000) {
			const uintptr_t potentialBase = searchForward ? base + i : base - i;
			PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(potentialBase);

			// Check if page is readable
			MEMORY_BASIC_INFORMATION mbi;
			ZeroMemory(&mbi, sizeof(mbi));
			if (VirtualQuery(dosHeader, &mbi, sizeof(mbi)) != sizeof(mbi) ||
				!isPageReadable(&mbi)) {
				continue;
			}

			if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
				continue;
			}

			PIMAGE_NT_HEADERS64 ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(
				reinterpret_cast<uint8_t*>(dosHeader) + dosHeader->e_lfanew
				);
			if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
				continue;
			}

			return reinterpret_cast<void*>(potentialBase);
		}

		// Not found, try and look at the prev set of pages
		// Case:
		//		0x00007FF75DDF0000		<-- IMAGEBASE
		//		0x00007FF75DE03D80		<-- me
		if (searchForward) {
			return getImageBase(addr, false);
		}

		return nullptr;
	}

	/// Returns the section name that contains memPtr
	std::string getSectionName(void* memPtr) {
		void* imageBase = getImageBase(memPtr);
		if (!imageBase) {
			LOG("Cannot locate image base");
			return "<invalid>";
		}

		LOG("Ptr=0x%p imgBase=0x%p", memPtr, imageBase);

		PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase);
		if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
			return "<invalid>";
		}

		PIMAGE_NT_HEADERS64 ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(
			reinterpret_cast<uintptr_t>(dosHeader) + dosHeader->e_lfanew
			);
		if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
			return "<invalid>";
		}

		PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
		for (unsigned i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
			uintptr_t sectionStart = reinterpret_cast<uintptr_t>(imageBase) + section->VirtualAddress;
			uintptr_t sectionEnd = sectionStart + section->Misc.VirtualSize;
			if (reinterpret_cast<uintptr_t>(memPtr) >= sectionStart &&
				reinterpret_cast<uintptr_t>(memPtr) < sectionEnd) {
				char name[9] = { 0 };
				memcpy(name, section->Name, 8);
				return std::string(name);
			}
		}

		return "<unknown>";
	}

	/// Prints the disassembly of a function
	/// Stops at padding
	void printFunctionDisassembly(void* function) {
		std::string sectionName = getSectionName(function);

		size_t offset = 0;
		uint8_t* curByte;
		while (*(curByte = reinterpret_cast<uint8_t*>(function) + offset) != 0xCC) {
			nmd_x86_instruction instruction;
			if (nmd_x86_decode(curByte,
							   NMD_X86_MAXIMUM_INSTRUCTION_LENGTH,
							   &instruction,
							   NMD_X86_MODE_64,
							   NMD_X86_DECODER_FLAGS_MINIMAL)) {
				char formattedInstruction[128];
				nmd_x86_format(
					&instruction,
					formattedInstruction,
					reinterpret_cast<uintptr_t>(curByte),
					NMD_X86_FORMAT_FLAGS_DEFAULT | NMD_X86_FORMAT_FLAGS_UPPERCASE
				);
				LOG("%s:%016zX\t%s", sectionName.c_str(),
					reinterpret_cast<uintptr_t>(function) + offset, formattedInstruction);

				offset += instruction.length;
			}
		}
	}

	void* findRemotePattern(
		HANDLE hProc,
		void* regionStart,
		size_t regionLen,
		const char* pattern,
		size_t patternLen,
		const char* mask
	) {
		if (!hProc || hProc == INVALID_HANDLE_VALUE || !regionStart || regionLen == 0 || !pattern || patternLen == 0) {
			return nullptr;
		}

		// Validate mask
		size_t maskLen = static_cast<size_t>(-1);
		if (mask && (maskLen = strlen(mask)) != patternLen) {
			LOG("Pattern and mask length mismatch Pattern=%s Mask=%s",
				ARR(reinterpret_cast<const unsigned char*>(pattern), patternLen),
				ARR(mask, maskLen));
			return nullptr;
		}

		uintptr_t searchStart = reinterpret_cast<uintptr_t>(regionStart);
		uintptr_t searchEnd = searchStart + regionLen;
		uintptr_t curPageAddr = searchStart & ~0xFFF;

		MEMORY_BASIC_INFORMATION mbi;
		for (; curPageAddr < searchEnd; ) {
			ZeroMemory(&mbi, sizeof(mbi));

			// Check page readable
			if (VirtualQueryEx(hProc, reinterpret_cast<void*>(curPageAddr), &mbi, sizeof(mbi)) != sizeof(mbi)) {
				LOG("VirtualQueryEx failed at 0x%zX, skipping page", curPageAddr);
				curPageAddr += 0x1000;
				continue;
			}

			if (!isPageReadable(&mbi)) {
				curPageAddr += mbi.RegionSize;
				continue;
			}

			// Read pages
			const size_t regionSize = mbi.RegionSize;
			std::vector<uint8_t> buffer(regionSize);
			if (!ReadProcessMemory(hProc, reinterpret_cast<void*>(curPageAddr), buffer.data(), regionSize, nullptr)) {
				LOG("Failed to read region at 0x%zX", curPageAddr);
				curPageAddr += regionSize;
				continue;
			}

			// Search for pattern in this region
			uintptr_t patternStart = max(curPageAddr, searchStart);
			uintptr_t patternEnd = min(curPageAddr + regionSize, searchEnd);

			VLOG("Searching region 0x%zX-0x%zX (size=0x%zX)",
				 curPageAddr, curPageAddr + regionSize, regionSize);

			for (; patternStart + patternLen <= patternEnd; patternStart++) {
				// Test pattern
				bool found = true;
				for (size_t i = 0; i < patternLen; i++) {
					size_t bufferIndex = (patternStart - curPageAddr) + i;
					uint8_t memByte = buffer[bufferIndex];
					uint8_t patternByte = static_cast<uint8_t>(pattern[i]);

					if (patternByte != memByte && (!mask || mask[i] != '?')) {
						found = false;
						break;
					}
				}

				if (found) {
					return reinterpret_cast<void*>(patternStart);
				}
			}

			curPageAddr += regionSize;
		}

		return nullptr;
	}

}