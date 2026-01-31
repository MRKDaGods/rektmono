#include "patch.h"
#include "remote/runtime_data.h"
#include "remote/hook.h"

namespace mrk::patch {

	bool initialize(
		const ProcessInfo& procInfo,
		void* runtimeDataAddr,
		const mono::MonoProcs* monoProcs
	) {
		if (!procInfo.hProcess || !procInfo.hThread || !runtimeDataAddr || !monoProcs) {
			return false;
		}

		LOG("Allocating hook functions...");
		mono::MonoProcs hookedProcs;
		if (!detail::allocateHookFunctions(procInfo.hProcess, runtimeDataAddr, monoProcs, hookedProcs)) {
			LOG("Failed to allocate hook functions");
			return false;
		}
		LOG("Hook functions allocated successfully");
		LOG("hooked do_mono_image_open at 0x%p", static_cast<void*>(hookedProcs.do_mono_image_open));
		LOG("hooked mono_image_open_from_data_with_name at 0x%p", static_cast<void*>(hookedProcs.mono_image_open_from_data_with_name));

		LOG("Applying hooks...");
		if (!detail::applyHooks(procInfo.hProcess, monoProcs, hookedProcs)) {
			LOG("Failed to apply hooks");
			return false;
		}

		return true;
	}

	namespace detail {

		bool allocateHookFunctions(
			HANDLE hProc,
			void* runtimeDataAddr,
			const mono::MonoProcs* originalProcs,
			mono::MonoProcs& hookedProcs
		) {
			if (!hProc || !runtimeDataAddr || !originalProcs) {
				return false;
			}

			// Clear hookedProcs
			ZeroMemory(&hookedProcs, sizeof(hookedProcs));

			// Allocate both functions
			// do_mono_image_open
			if (!allocatePersistentRemoteFunction(
				hProc,
				reinterpret_cast<uint8_t*>(&remote_detail::hookedDoMonoImageOpen),
				runtimeDataAddr,
				reinterpret_cast<PersistentRemoteFunction*>(&hookedProcs.do_mono_image_open),
				nullptr
			)) {
				LOG("Failed to allocate persistent function: hookedDoMonoImageOpen");
				return false;
			}

			// mono_image_open_from_data_with_name
			if (!allocatePersistentRemoteFunction(
				hProc,
				reinterpret_cast<uint8_t*>(&remote_detail::hookedMonoImageOpenFromData),
				runtimeDataAddr,
				reinterpret_cast<PersistentRemoteFunction*>(&hookedProcs.mono_image_open_from_data_with_name),
				nullptr
			)) {
				LOG("Failed to allocate persistent function: hookedMonoImageOpenFromData");
				return false;
			}

			return true;
		}

		bool applyHooks(
			HANDLE hProc,
			const mono::MonoProcs* originalProcs,
			const mono::MonoProcs& hookedProcs
		) {
			// do_mono_image_open
			if (!remoteHook(hProc, originalProcs->do_mono_image_open, hookedProcs.do_mono_image_open, nullptr)) {
				LOG("Failed to hook do_mono_image_open");
				return false;
			}
			LOG("Successfully hooked do_mono_image_open");

			// mono_image_open_from_data_with_name
			if (!remoteHook(hProc, originalProcs->mono_image_open_from_data_with_name, hookedProcs.mono_image_open_from_data_with_name, nullptr)) {
				LOG("Failed to hook mono_image_open_from_data_with_name");
				return false;
			}
			LOG("Successfully hooked mono_image_open_from_data_with_name");

			return true;
		}

	} // namespace detail

	namespace remote_detail {

		REMOTE_HOOKED_FUNCTION(
			hookedDoMonoImageOpen,
			void* alc,
			const char* fname,
			mono::MonoImageOpenStatus* status,
			int care_about_cli,
			int care_about_pecoff,
			int refonly,
			int metadata_only,
			int load_from_context
		) {
			auto* runtimeData = REMOTE_HOOKED_RUNTIME_DATA();
			runtimeData->winapi.MessageBoxA(nullptr, fname, "HOOKED do_mono_image_open", MB_OK);
			return 0;
		}

		REMOTE_HOOKED_FUNCTION(
			hookedMonoImageOpenFromData,
			char* data,
			unsigned int data_len,
			int need_copy,
			mono::MonoImageOpenStatus* status,
			int refonly,
			const char* name
		) {
			auto* runtimeData = REMOTE_HOOKED_RUNTIME_DATA();
			runtimeData->winapi.MessageBoxA(nullptr, name, "HOOKED mono_image_open_from_data_with_name", MB_OK);
			return 0;
		}

	} // namespace remote_detail

} // namespace mrk::patch

// yeah ik, im working on my comments lmao
