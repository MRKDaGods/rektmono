#pragma once

#include <cstdint>
#include <Windows.h>

namespace mrk {
	struct LoaderConfig;

	class Core {
	public:
		explicit Core(LoaderConfig* config);
		~Core();

		void cleanup();
		bool execute();

	private:
		LoaderConfig* config_;
		uint8_t* payloadData_;

		PIMAGE_DOS_HEADER payloadDosHeader_;
		PIMAGE_NT_HEADERS payloadNtHeaders_;

		HANDLE procHandle_;
		HANDLE thHandle_;

		struct {
			void* moduleBase;
			void* paramsBase;
			void* shellcodeBase;
		} fixupShellcodeSetup_;

		struct {
			void* returnCodeBase;
			void* completionFlagBase;
			void* shellcodeBase;
		} loaderShellcodeSetup_;

		bool createSuspendedProcess();
		bool validatePayloadHeaders();
		bool allocateAndCopyPayload();
		bool injectFixupShellcode();
		bool injectLoaderShellcode();
		bool executeLoaderShellcode();
	};
}