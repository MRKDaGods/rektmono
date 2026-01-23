#include "logger.h"
#include "remote/runtime.h"

#include <Windows.h>

using namespace mrk;

REMOTE_FUNCTION(CustomRemoteFunction) {
	auto mbox = REMOTE_ARG(1, decltype(&MessageBoxA));
	auto text = REMOTE_ARG(2, const char*);
	auto caption = REMOTE_ARG(3, const char*);

	auto getProcId = REMOTE_ARG(4, decltype(&GetCurrentProcessId));
	DWORD pid = getProcId();

	auto wsprintfF = REMOTE_ARG(5, decltype(&wsprintfA));
	auto pidBuffer = REMOTE_ARG(6, char*);
	auto fmtString = REMOTE_ARG(7, const char*);

	wsprintfF(pidBuffer, fmtString, pid);
	mbox(nullptr, pidBuffer, caption, MB_OK);
	
	return 42;
}

int demo_main() {
	LOG("Injectionless sex - %s", __TIMESTAMP__);

	if (!isInjectionlessSexSupported()) {
		LOG("Injectionless sex is not supported on this architecture.");
		return 1;
	}

	// We will be doing this in notepad
	STARTUPINFO si;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(STARTUPINFO);

	PROCESS_INFORMATION pi;
	ZeroMemory(&pi, sizeof(pi));

	LOG("Creating notepad process...");
	if (!CreateProcessA("C:\\Windows\\System32\\notepad.exe", nullptr, nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
		LOG("Failed to start notepad. Error: %lu", GetLastError());
		return 1;
	}
	LOG("Notepad process created successfully. PID: %lu", pi.dwProcessId);

	LOG("Resuming thread and waiting for initialization...");
	ResumeThread(pi.hThread);
	Sleep(3000);

	LOG("Starting remote function call...");
	bool success = false;
	
	LOG("Calling CustomRemoteFunction with automatic buffer allocation...");
	success = callRemoteFunction(pi.hProcess, pi.hThread, nullptr, CustomRemoteFunction, 
		MessageBoxA, "xanz", "WORKS!", GetCurrentProcessId, wsprintfA, remote::stackalloc(256), "Process ID: %lu");
	LOG("Remote function call completed. Success: %d", (int)success);

	Sleep(1000);

	LOG("Cleaning up and exiting...");
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return success ? 0 : 1;
}