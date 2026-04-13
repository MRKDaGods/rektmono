#pragma once

#include <Windows.h>
#include <cstdint>
#include <vector>
#include <string>

namespace mrk {

	/// String reference found in a function
	struct StringReference {
		size_t offsetInFunction;	// Offset in function where the address is stored
		const char* localString;	// Pointer to local string
		void* remoteString;			// Allocated remote string address
		size_t stringLength;		// Length including null terminator
	};

	/// Context for managing strings in a persistent remote function
	struct PersistentFunctionStringContext {
		std::vector<StringReference> strings;
		void* stringDataBlock;
		size_t stringDataBlockSize;
	};

	/// Scan a function for string references and allocate them in remote process
	bool scanAndPatchStrings(
		HANDLE hProc,
		void* remoteFuncBase,
		const uint8_t* originalFunctionBuffer,	// Must point to the original function for correct disp calculation
		uint8_t* patchBuffer,
		size_t functionSize,
		PersistentFunctionStringContext* outContext
	);

	/// Free strings allocated for a persistent function
	void freePersistentFunctionStrings(HANDLE hProc, PersistentFunctionStringContext& context);

}
