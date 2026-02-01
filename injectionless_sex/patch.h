#pragma once

#include "mono.h"
#include "remote/hook.h"

namespace mrk::patch {

	/// Trampoline indices
	enum TRAMPOLINE_INDEX {
		TRAMPOLINE_INDEX_do_mono_image_open = 0,
		TRAMPOLINE_INDEX_mono_image_open_from_data_with_name = 1,

		TRAMPOLINE_INDEX_COUNT
	};

	/// Allocates and applies the hooks
	bool initialize(
		const ProcessInfo& procInfo,
		void* runtimeDataAddr,
		const mono::MonoProcs* monoProcs
	);

	namespace detail {

		/// Allocates hook functions in the target process
		bool allocateHookFunctions(
			HANDLE hProc,
			void* runtimeDataAddr,
			const mono::MonoProcs* originalProcs,
			mono::MonoProcs& hookedProcs
		);

		bool applyHooks(
			HANDLE hProc,
			void* runtimeDataAddr,
			const mono::MonoProcs* originalProcs,
			const mono::MonoProcs& hookedProcs
		);

		bool writeTrampolineMapEntry(
			HANDLE hProc,
			void* runtimeDataAddr,
			TRAMPOLINE_INDEX index,
			void* trampoline
		);

		/// Debug
		void printRemoteTrampolineMap(HANDLE hProc, void* runtimeDataAddr);
	
	}

	namespace remote_detail {

		/// Hooked do_mono_image_open
		REMOTE_PERSISTENT_FUNCTION(
			hookedDoMonoImageOpen,
			void* alc,
			const char* fname,
			mono::MonoImageOpenStatus* status,
			int care_about_cli,
			int care_about_pecoff,
			int refonly,
			int metadata_only,
			int load_from_context
		);

		/// Hooked mono_image_open_from_data_with_name
		REMOTE_PERSISTENT_FUNCTION(
			hookedMonoImageOpenFromData,
			char* data,
			unsigned int data_len,
			int need_copy,
			mono::MonoImageOpenStatus* status,
			int refonly,
			const char* name
		);

	}

}