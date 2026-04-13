#pragma once

// mscorlib, etc use do_mono_image_open
// unity assemblies use mono_image_open_from_data

#include "remote/runtime.h"

#include <Windows.h>

namespace mrk::mono {

	typedef struct _MonoImage MonoImage;
	typedef int MonoImageOpenStatus;

	typedef MonoImage* (__stdcall* do_mono_image_open_t)(
		void* alc,
		const char* fname,
		MonoImageOpenStatus* status, int care_about_cli,
		int care_about_pecoff,
		int refonly,
		int metadata_only,
		int load_from_context
	);

	typedef MonoImage* (__stdcall* mono_image_open_from_data_with_name_t)(
		char* data,
		unsigned int data_len,
		int need_copy,
		MonoImageOpenStatus* status,
		int refonly,
		const char* name
	);

	struct MonoProcs {
		do_mono_image_open_t do_mono_image_open;
		mono_image_open_from_data_with_name_t mono_image_open_from_data_with_name;
	};

	bool initialize(
		const ProcessInfo& procInfo,
		void* runtimeDataAddr,
		const char* monoRelativePath,
		MonoProcs* monoProcs
	);

	namespace detail {

		bool resolveDoMonoImageOpen(
			HANDLE hProc,
			void* monoBaseAddr,
			size_t monoSz,
			MonoProcs* monoProcs
		);

	}

	// Remote implementations
	namespace remote_detail {

		/// Loads mono in the target process
		/// Returns its module base and proxy handle
		REMOTE_FUNCTION(loadMono);

		/// Remotely resolves mono_image_open_from_data_with_name
		REMOTE_FUNCTION(resolveMonoImageOpenFromDataWithName);

	}

}