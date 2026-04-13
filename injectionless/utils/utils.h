#pragma once

#include <string>
#include <Windows.h>

namespace mrk {
	
	bool isAddressReadable(void* addr);
	std::string getSectionName(void* memPtr);
	void printFunctionDisassembly(void* function);
	
	void* findRemotePattern(
		HANDLE hProc,
		void* start,
		size_t len,
		const char* pattern,
		size_t patternLen,
		const char* mask
	);

}