#include "main.h"

typedef BOOL(__stdcall* tVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
tVirtualProtect oVirtualProtect;

BOOL __stdcall hkVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
	if (reinterpret_cast<uintptr_t>(lpAddress) == 0x5241C2)
	{
		uintptr_t uiModule = ((reinterpret_cast<uintptr_t>(_ReturnAddress()) >> 16) - 2) * 0x10000;
		memcpy(reinterpret_cast<void*>(uiModule + 0x87D9), "\xC2\x18\x00", 3);
		memcpy(reinterpret_cast<void*>(uiModule + 0xB936), "\xC2\x08\x00", 3);
		memcpy(reinterpret_cast<void*>(uiModule + 0xCFA7), "\x90\x90\x90\x90\x90", 5);
		memcpy(reinterpret_cast<void*>(uiModule + 0xAB3F), "\x90\x90\x90\x90\x90", 5);
		memcpy(reinterpret_cast<void*>(uiModule + 0x27AF1), "\xB0\x01\xC3", 3);
	}

	return oVirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
}

void MainThread()
{
	MH_Initialize();
	MH_CreateHook(reinterpret_cast<void*>(VirtualProtect), &hkVirtualProtect, reinterpret_cast<void**>(&oVirtualProtect));
	MH_EnableHook(MH_ALL_HOOKS);
	ExitThread(EXIT_SUCCESS);
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(hModule);
		CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(MainThread), nullptr, 0, nullptr);
	}

	return TRUE;
}

