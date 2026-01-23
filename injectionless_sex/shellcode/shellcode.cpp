#include "shellcode.h"
#include "../logger.h"

#include <cstring>

namespace mrk {
	// 0xAAAAAAAAAAAAAAAA -> remoteFunction address
	// 0xCCCCCCCCCCCCCCCC -> params address
	// 0xDDDDDDDDDDDDDDDD -> return code address
	// 0xEEEEEEEEEEEEEEEE -> completion flag address
	const uint8_t execShellcode[] = {
		// Align stack
		0x48, 0xB8, 0xF0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,		// mov    rax, -16
		0x48, 0x21, 0xC4,												// and    rsp, rax

		// Allocate shadow space
		0x48, 0x83, 0xEC, 0x20,											// sub    rsp, 0x20

		// Load parameters
		0x48, 0xB9, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,		// mov	  rcx, 0xcccccccccccccccc
		0x48, 0xB8, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,		// mov    rax, 0xaaaaaaaaaaaaaaaa
		0xFF, 0xD0,														// call   rax

		// Store return code
		0x49, 0xBA, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD,		// mov    r10, 0xdddddddddddddddd
		0x41, 0x89, 0x02,												// mov    DWORD PTR [r10], eax

		// Mark completed
		0x49, 0xBB, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE,		// mov    r11, 0xeeeeeeeeeeeeeeee
		0x41, 0xC7, 0x03, 0xF1, 0xF1, 0xEA, 0xD1,						// mov    DWORD PTR [r11], 0xD1EAF1F1 // COMPLETION_FLAG_VALUE

		// Clean up stack
		0x48, 0x83, 0xC4, 0x20,											// add    rsp, 0x20

		// Infinite loop
		0xEB, 0xFE														// jmp    -2
	};

	void patchShellcode(uint8_t* shellcode, const ShellcodePatchSetup& setup) {
		// Copy original shellcode to local buffer
		memcpy(shellcode, execShellcode, sizeof(execShellcode));

		// Patch addresses
		for (size_t i = 0; i < sizeof(execShellcode) - sizeof(uintptr_t); i++) {
			uintptr_t* ptr = reinterpret_cast<uintptr_t*>((shellcode + i));
			switch (*ptr) {
				case 0xAAAAAAAAAAAAAAAA:
					*ptr = reinterpret_cast<uintptr_t>(setup.remoteFunctionAddress);
					LOG("Set remote function address: 0x%llX", static_cast<unsigned long long>(*ptr));
					break;

				case 0xCCCCCCCCCCCCCCCC:
					*ptr = reinterpret_cast<uintptr_t>(setup.paramsAddress);
					LOG("Set params address: 0x%llX", static_cast<unsigned long long>(*ptr));
					break;

				case 0xDDDDDDDDDDDDDDDD:
					*ptr = reinterpret_cast<uintptr_t>(setup.returnCodeAddress);
					LOG("Set return code address: 0x%llX", static_cast<unsigned long long>(*ptr));
					break;

				case 0xEEEEEEEEEEEEEEEE:
					*ptr = reinterpret_cast<uintptr_t>(setup.completionFlagAddress);
					LOG("Set completion flag address: 0x%llX", static_cast<unsigned long long>(*ptr));
					break;
			}
		}
	}
}