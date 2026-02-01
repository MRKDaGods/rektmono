#include "runtime_data.h"
#include "args.h"

namespace mrk {

	namespace remote_detail {
		// Compiler is smart enough to not allocate the ptr refs on the stack
		// Would cause a crash otherwise
		File* __stdcall ReadFile(const char* path) {
			auto runtimeData = REMOTE_PERSISTENT_RUNTIME_DATA();

			HANDLE hFile = runtimeData->winapi.CreateFileA(
				path,
				GENERIC_READ,
				FILE_SHARE_READ,
				nullptr,
				OPEN_EXISTING,
				FILE_ATTRIBUTE_NORMAL,
				nullptr
			);
			if (!hFile || hFile == INVALID_HANDLE_VALUE) {
				return nullptr;
			}

			LARGE_INTEGER* fileSize = RUNTIME_STACK(0, LARGE_INTEGER);
			if (!runtimeData->winapi.GetFileSizeEx(hFile, fileSize)) {
				runtimeData->winapi.CloseHandle(hFile);
				return nullptr;
			}

			// Allocate file buffer
			BYTE* fileBuffer = *RUNTIME_STACK(sizeof(LARGE_INTEGER), BYTE*) = reinterpret_cast<BYTE*>(
				runtimeData->winapi.VirtualAlloc(
					nullptr,
					static_cast<SIZE_T>(fileSize->LowPart),
					MEM_COMMIT | MEM_RESERVE,
					PAGE_READWRITE
				)
			);
			if (!fileBuffer) {
				runtimeData->winapi.CloseHandle(hFile);
				return nullptr;
			}

			DWORD* bytesRead = RUNTIME_STACK(sizeof(LARGE_INTEGER) + sizeof(BYTE*), DWORD);
			if (!runtimeData->winapi.ReadFile(
				hFile,
				fileBuffer,
				fileSize->LowPart,
				bytesRead,
				nullptr
			) || *bytesRead != fileSize->LowPart) {
				runtimeData->winapi.CloseHandle(hFile);
				runtimeData->winapi.VirtualFree(fileBuffer, 0, MEM_RELEASE);
				return nullptr;
			}

			// Close file
			runtimeData->winapi.CloseHandle(hFile);

			// Allocate file and return !!
			File* karma = reinterpret_cast<File*>(
				runtimeData->winapi.VirtualAlloc(
					nullptr,
					sizeof(File),
					MEM_COMMIT | MEM_RESERVE,
					PAGE_READWRITE
				)
			);
			if (!karma) {
				runtimeData->winapi.VirtualFree(fileBuffer, 0, MEM_RELEASE);
				return nullptr;
			}

			karma->bytes = fileBuffer;
			karma->sz = static_cast<size_t>(fileSize->LowPart);

			return karma; // Karma?
		}

	} // namespace remote_detail

} // namespace mrk
