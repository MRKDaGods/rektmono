#pragma once

#include <cstdint>

// Shellcode execution completion flag value
constexpr auto COMPLETION_FLAG_VALUE = 0xD1EAF1F1;

namespace mrk {
	constexpr size_t EXEC_SHELLCODE_SIZE = 0x4B;
	extern uint8_t execShellcode[];

	struct ShellcodePatchSetup {
		void* remoteFunctionAddress;
		void* paramsAddress;
		void* returnCodeAddress;
		void* completionFlagAddress;
	};

	void patchShellcode(uint8_t* shellcode, const ShellcodePatchSetup& setup);
}