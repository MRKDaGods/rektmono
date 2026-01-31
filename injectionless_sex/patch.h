#pragma once

#include "mono.h"
#include "remote/hook.h"

namespace mrk::patch {

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
			const mono::MonoProcs* originalProcs,
			const mono::MonoProcs& hookedProcs
		);
	
	}

	namespace remote_detail {

		/// Hooked do_mono_image_open
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
		);

		/// Hooked mono_image_open_from_data_with_name
		REMOTE_HOOKED_FUNCTION(
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