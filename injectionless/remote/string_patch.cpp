#include "string_patch.h"
#include "../logger.h"
#include "../utils/nmd_assembly.h"
#include "../utils/utils.h"

#include <algorithm>

#define MAX_STR_LEN 256

namespace mrk {

	//int dumbmf = 0;

	/// Checks if address lives inside rdata
	bool sehSafeIsInRdata(uintptr_t address, bool& imageBaseError) {
		LOG("Checking if address 0x%zX is in .rdata section...", address);
		std::string section = getSectionName(reinterpret_cast<void*>(address));
		
		/*if (dumbmf++ == 1) {
			section = "<invalid>";
		}*/

		// Invalid image base means you fucked up :P
		if (section == "<invalid>") {
			// Cannot locate imagebase
			// String allocations wont work
			// Dont hook!
			imageBaseError = true;
			return false;

			// throw std::runtime_error("Cannot locate image base!");
		}

		return section == ".rdata";
	}

	bool isLikelyStringPointer(uintptr_t address, bool& imageBaseError) {
		// If null or out of user va range
		if (address == 0 || address > 0x00007FFF'FFFFFFFF) {
			return false;
		}

		// Must be in rdata
		if (!sehSafeIsInRdata(address, imageBaseError)) {
			return false;
		}

		__try {
			// Try read str upto MAX_STR_LEN chars
			const char* str = reinterpret_cast<const char*>(address);
			for (unsigned i = 0; i < MAX_STR_LEN; i++) {
				char c = str[i];

				// If we got a null term, then we're good to go
				if (c == '\0') {
					return true;
				}

				// Check if valid ascii
				if (!isascii(c)) {
					return false;
				}
			}

			// May be valid but greater than MAX_STR_LEN
			return false;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return false;
		}
	}

	/// Extract string references from function using disassembly
	bool scanAndPatchStrings(
		HANDLE hProc,
		void* remoteFuncBase,
		const uint8_t* originalFunctionBuffer,
		uint8_t* patchBuffer,
		size_t functionSize,
		PersistentFunctionStringContext* outContext
	) {
		LOG("Scanning function for string references (size=%zu)...", functionSize);

		PersistentFunctionStringContext context;
		context.stringDataBlock = nullptr;
		context.stringDataBlockSize = 0;

		// Look for LEA instructions that load addresses from rdata
		size_t offset = 0;
		std::vector<StringReference> foundStrings;
		bool imageBaseError = false;

		while (offset < functionSize) {
			nmd_x86_instruction instruction;

			if (!nmd_x86_decode(
				originalFunctionBuffer + offset,
				functionSize - offset,
				&instruction,
				NMD_X86_MODE_64,
				NMD_X86_DECODER_FLAGS_MINIMAL
			)) {
				offset++;
				continue;
			}

			// Check for LEA with RIP addressing
			// 48/9 8D & mod=00 rm=101
			if (instruction.opcode == 0x8D &&
				instruction.modrm.fields.mod == 0b00 &&
				instruction.modrm.fields.rm == 0b101) {
				int32_t displacement = instruction.displacement;
				uintptr_t stringAddr = reinterpret_cast<uintptr_t>(originalFunctionBuffer) +
					offset + instruction.length + displacement;

				VLOG("Found LEA [rip+disp] at offset 0x%zX, displacement=%d, target=0x%p",
					 offset, displacement, (void*)stringAddr);

				if (isLikelyStringPointer(stringAddr, imageBaseError)) {
					const char* str = reinterpret_cast<const char*>(stringAddr);
					size_t strLen = strlen(str) + 1;

					StringReference ref;
					ref.offsetInFunction = offset;
					ref.localString = str;
					ref.remoteString = nullptr;
					ref.stringLength = strLen;

					foundStrings.push_back(ref);
					LOG("Found string via LEA at offset 0x%zX: \"%s\" (len=%zu)", offset, str, strLen);
				}

				// Fatal !!
				if (imageBaseError) {
					return false;
				}
			}

			offset += instruction.length;
		}

		if (foundStrings.empty()) {
			LOG("No string references found in function");
			*outContext = context;
			return true;
		}

		LOG("Found %zu string reference(s), allocating remote memory...", foundStrings.size());

		// Calculate total size needed for all strings
		size_t totalStringSize = 0;
		for (const auto& ref : foundStrings) {
			totalStringSize += ref.stringLength;
		}

		// Allocate single block for all strings near remote allocation
		void* remoteStringBlock = nullptr;
		const void* addresses[3] = { 
			remoteFuncBase,
			reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(remoteFuncBase) + 0x1000), // Next page
			NULL
		};

		for (unsigned i = 0; i < 3 && !remoteStringBlock; i++) {
			remoteStringBlock = VirtualAllocEx(
				hProc,
				const_cast<void*>(addresses[i]),
				totalStringSize,
				MEM_COMMIT | MEM_RESERVE,
				PAGE_READWRITE
			);
		}

		if (!remoteStringBlock) {
			LOG("Failed to allocate remote string block. Error: %lu", GetLastError());
			return false;
		}

		LOG("Allocated remote string block at 0x%p size=%zu disp=%zu", 
			remoteStringBlock, 
			totalStringSize, 
			reinterpret_cast<uintptr_t>(remoteStringBlock) - reinterpret_cast<uintptr_t>(remoteFuncBase));

		// Copy strings to remote process and update references
		uintptr_t currentRemoteAddr = reinterpret_cast<uintptr_t>(remoteStringBlock);
		for (auto& ref : foundStrings) {
			// Write string to remote process
			if (!WriteProcessMemory(
				hProc,
				reinterpret_cast<void*>(currentRemoteAddr),
				ref.localString,
				ref.stringLength,
				nullptr
			)) {
				LOG("Failed to write string to remote process. Error: %lu", GetLastError());
				VirtualFreeEx(hProc, remoteStringBlock, 0, MEM_RELEASE);
				return false;
			}

			ref.remoteString = reinterpret_cast<void*>(currentRemoteAddr);
			LOG("Wrote string \"%s\" to remote address 0x%p", ref.localString, ref.remoteString);

			currentRemoteAddr += ref.stringLength;
		}

		// Patch LEA displacement to point to remote strings
		for (const auto& ref : foundStrings) {
			nmd_x86_instruction instruction;
			nmd_x86_decode(
				patchBuffer + ref.offsetInFunction,
				functionSize - ref.offsetInFunction,
				&instruction,
				NMD_X86_MODE_64,
				NMD_X86_DECODER_FLAGS_MINIMAL
			);
			
			// Calculate new disp
			// target - (instruction address + instruction length)
			uintptr_t remoteInstructionAddr = reinterpret_cast<uintptr_t>(remoteFuncBase) + ref.offsetInFunction;
			uintptr_t remoteStringAddr = reinterpret_cast<uintptr_t>(ref.remoteString);
			int64_t newDisp = remoteStringAddr - (remoteInstructionAddr + instruction.length);

			// Validate disp
			if (newDisp < INT32_MIN || newDisp > INT32_MAX) {
				LOG("Error patching LEA, string at 0x%p is too far from instruction at 0x%p (displacement=%lld)",
					ref.remoteString, (void*)remoteInstructionAddr, newDisp);
				VirtualFreeEx(hProc, remoteStringBlock, 0, MEM_RELEASE);
				return false;
			}

			// Patch disp
			// REX.W + opcode + modrm + disp
			uint8_t* patchedInstruction = patchBuffer + ref.offsetInFunction;
			*reinterpret_cast<int32_t*>(patchedInstruction + 3) = static_cast<int32_t>(newDisp);

			LOG("Patched LEA at offset 0x%zX: new displacement=%d, remote string=0x%p",
				ref.offsetInFunction, static_cast<int32_t>(newDisp), ref.remoteString);
		}

		// Set up context
		context.strings = foundStrings;
		context.stringDataBlock = remoteStringBlock;
		context.stringDataBlockSize = totalStringSize;

		*outContext = context;

		LOG("Successfully patched %zu string reference(s)", foundStrings.size());
		return true;
	}

	void freePersistentFunctionStrings(HANDLE hProc, PersistentFunctionStringContext& context) {
		if (context.stringDataBlock) {
			VLOG("Freeing remote string block at 0x%p (size=%zu)",
				 context.stringDataBlock, context.stringDataBlockSize);
			VirtualFreeEx(hProc, context.stringDataBlock, 0, MEM_RELEASE);
			context.stringDataBlock = nullptr;
		}

		context.strings.clear();
		context.stringDataBlockSize = 0;
	}

}
