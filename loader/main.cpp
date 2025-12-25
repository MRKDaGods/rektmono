#include "../common.h"
#include "b64.h"
#include "config.h"
#include "core.h"
#include "logger.h"

#include <Windows.h>

char* findArgument(int argc, char** argv, const char* key) {
	// --config=XXXXXXXXX
	size_t keyLen = strlen(key);

	for (int i = 1; i < argc; i++) {
		if (strncmp(argv[i], key, keyLen) == 0) {
			return argv[i] + keyLen;
		}
	}

	return nullptr;
}

int main(int argc, char** argv) {
	// Find config
	char* encodedConfig = findArgument(argc, argv, "--config=");
	if (!encodedConfig) {
		LOG("No config argument provided.");
		return 1;
	}

	mrk::LoaderConfig* config = mrk::loadConfig(encodedConfig);
	if (!config) {
		LOG("Failed to parse config.");
		return 1;
	}

	LOG("Magic=0x%X Path=%s", config->magic, config->processPath);
	
	mrk::Core core(config);
	if (core.execute()) {
		LOG("rektmono loaded successfully!");
	}
	else {
		LOG("Failed to load rektmono.");
	}

	LOG("Cleaning up...");

	core.cleanup();
	delete config;
	
	return 0;	
}