#include "config.h"
#include "b64.h"
#include "../common.h"

#include <vector>

namespace mrk {
	LoaderConfig* loadConfig(const char* encodedConfigBase64) {
		auto view = std::string_view(encodedConfigBase64);
		auto decoded = base64::decode_into<std::vector<uint8_t>>(view);
		auto decodedConfig = reinterpret_cast<LoaderConfig*>(decoded.data());

		// Validate magic
		if (decodedConfig->magic != CONFIG_MAGIC) {
			return nullptr;
		}

		// Alloc and copy
		LoaderConfig* config = new LoaderConfig();
		memcpy(config, decodedConfig, sizeof(LoaderConfig));

		return config;
	}
}