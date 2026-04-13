#include "hook.h"

#define NMD_ASSEMBLY_IMPLEMENTATION
#include "../utils/nmd_assembly.h"

#define JMP_SZ 14

namespace mrk {

	void cleanupHookContext(HANDLE hProc, RemoteHookContext& ctx) {
		if (hProc == INVALID_HANDLE_VALUE) return;

		if (ctx.local.originalBytes) {
			delete[] ctx.local.originalBytes;
			ctx.local.originalBytes = nullptr;
		}
		ctx.local.originalBytesSz = 0;

		if (ctx.local.trampoline) {
			delete[] ctx.local.trampoline;
			ctx.local.trampoline = nullptr;
		}

		if (ctx.remote.trampoline) {
			VirtualFreeEx(hProc, ctx.remote.trampoline, 0, MEM_RELEASE);
			ctx.remote.trampoline = nullptr;
		}
		ctx.remote.trampolineSz = 0;
	}

	void createJmp(void* shellStart, void* dest) {
		static const uint8_t shellcode[] = {
			0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,					// jmp QWORD PTR [rip]
			0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0xAF, 0x1F		// 0xAABBCCDDEEFFAF1F
		};

		memcpy(shellStart, shellcode, JMP_SZ);
		memcpy(reinterpret_cast<uint8_t*>(shellStart) + 6, &dest, sizeof(dest));
	}

#pragma warning(push)
#pragma warning(disable : 6385 6387)

	bool remoteHook(HANDLE hProc, void* srcFunction, void* targetFunction, RemoteHookContext* outCtx) {
		LOG("Hooking src=0x%p target=0x%p", srcFunction, targetFunction);

		RemoteHookContext ctx;
		ZeroMemory(&ctx, sizeof(ctx));

		// Calculate how many bytes we need to copy
		uint8_t instructionBuffer[NMD_X86_MAXIMUM_INSTRUCTION_LENGTH]; // Temporary hold current remote instruction

		while (ctx.local.originalBytesSz < JMP_SZ) {
			// Read potential instruction
			if (!ReadProcessMemory(
				hProc,
				reinterpret_cast<uint8_t*>(srcFunction) + ctx.local.originalBytesSz,
				instructionBuffer,
				sizeof(instructionBuffer),
				nullptr
			)) {
				LOG("Failed to read instruction buffer. Error: %lu", GetLastError());
				return false;
			}

			size_t instructionLen = nmd_x86_ldisasm(
				instructionBuffer,
				sizeof(instructionBuffer),
				NMD_X86_MODE_64
			);

			if (instructionLen == 0) {
				LOG("Failed to disassemble instruction at offset %zu", ctx.local.originalBytesSz);
				break;
			}

			// Log what we're copying
			nmd_x86_instruction instruction;
			if (nmd_x86_decode(instructionBuffer, instructionLen, &instruction, NMD_X86_MODE_64, NMD_X86_DECODER_FLAGS_MINIMAL)) {
				char formattedInstruction[128];
				nmd_x86_format(
					&instruction,
					formattedInstruction,
					reinterpret_cast<uint64_t>(srcFunction) + ctx.local.originalBytesSz,
					NMD_X86_FORMAT_FLAGS_DEFAULT | NMD_X86_FORMAT_FLAGS_UPPERCASE
				);
				LOG("Copying instruction at +0x%zX: %s", ctx.local.originalBytesSz, formattedInstruction);
			}

			ctx.local.originalBytesSz += instructionLen;
		}

		ctx.local.originalBytes = new uint8_t[ctx.local.originalBytesSz];

		// Backup old bytes
		LOG("Reading %zu old bytes", ctx.local.originalBytesSz);
		if (!ReadProcessMemory(hProc, srcFunction, ctx.local.originalBytes, ctx.local.originalBytesSz, nullptr)) {
			LOG("Failed to read original bytes. Error: %lu", GetLastError());
			cleanupHookContext(hProc, ctx);
			return false;
		}

		LOG("Read: [%s]", ARR(ctx.local.originalBytes, ctx.local.originalBytesSz));

		// Jump to target in src function
		uint8_t srcJmpToTargetShellcode[JMP_SZ];
		createJmp(srcJmpToTargetShellcode, targetFunction);

		// Write shellcode to src function
		LOG("Writing jmp to target in src function...");
		DWORD oldProt;
		VirtualProtectEx(hProc, srcFunction, JMP_SZ, PAGE_EXECUTE_READWRITE, &oldProt);
		if (!WriteProcessMemory(hProc, srcFunction, srcJmpToTargetShellcode, sizeof(srcJmpToTargetShellcode), nullptr)) {
			LOG("Failed to write jmp to src function. Error: %lu", GetLastError());
			cleanupHookContext(hProc, ctx);
			VirtualProtectEx(hProc, srcFunction, JMP_SZ, oldProt, &oldProt);
			return false;
		}
		VirtualProtectEx(hProc, srcFunction, JMP_SZ, oldProt, &oldProt);

		// Create trampoline
		// Size of instructions we missed (wlnas el we missed bardo) + jump
		// Trampoline size = JMP_SZ + originalBytesSz
		const size_t trampolineSz = JMP_SZ + ctx.local.originalBytesSz;
		ctx.local.trampoline = new uint8_t[trampolineSz];

		// Copy original instructions
		memcpy(ctx.local.trampoline, ctx.local.originalBytes, ctx.local.originalBytesSz);

		// Jump back to src+originalBytesSz
		createJmp(reinterpret_cast<uint8_t*>(ctx.local.trampoline) + ctx.local.originalBytesSz,
				  reinterpret_cast<uint8_t*>(srcFunction) + ctx.local.originalBytesSz);

		// Allocate and copy trampoline in target process
		LOG("Allocating and writing trampoline (%zu bytes) in remote process...", trampolineSz);
		ctx.remote.trampoline = VirtualAllocEx(hProc, nullptr, trampolineSz, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		ctx.remote.trampolineSz = trampolineSz;

		if (!ctx.remote.trampoline) {
			LOG("Failed to allocate trampoline. Error: %lu", GetLastError());
			cleanupHookContext(hProc, ctx);
			return false;
		}
		LOG("Trampoline allocated at: 0x%p", ctx.remote.trampoline);
		
		if (!WriteProcessMemory(hProc, ctx.remote.trampoline, ctx.local.trampoline, trampolineSz, nullptr)) {
			LOG("Failed to write trampoline. Error: %lu", GetLastError());
			cleanupHookContext(hProc, ctx);
			return false;
		}
		LOG("Trampoline written at: 0x%p", ctx.remote.trampoline);

		// Cleanup local trampoline
		delete[] ctx.local.trampoline;
		ctx.local.trampoline = nullptr;

		// Return context
		if (outCtx) {
			*outCtx = ctx;
		}

		return true;
	}

#pragma warning(pop)

}