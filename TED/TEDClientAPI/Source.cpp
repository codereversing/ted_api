#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "iphlpapi.lib")

#include <Windows.h>

#include "Api.h"
#include "TEDClientBridge.h"

__declspec(dllexport) BOOL APIENTRY DllMain(HINSTANCE hModule, DWORD dwReason, LPVOID reserved)
{
	return TRUE;
}