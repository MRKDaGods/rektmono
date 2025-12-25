#pragma once

#include <cstdint>

namespace mrk {
	// Max path length 260
	typedef const char ConfigString[260];

	// Provided from launcher
	struct LoaderConfig {
		uint32_t magic;
		ConfigString processPath = {};
	};

	LoaderConfig* loadConfig(const char* encodedConfigBase64);
}