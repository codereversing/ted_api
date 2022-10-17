#pragma once

#ifndef TED_CLIENT_BRIDGE_H
#define TED_CLIENT_BRIDGE_H

#include <array>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>

#include <Windows.h>
#include <Psapi.h>

#include "Api.h"
#include "Structures.h"

extern "C"
{

using TED_CreateClientFncPtr = std::add_pointer<decltype(TED_CreateClient)>::type;
using TED_DestroyClientFncPtr = std::add_pointer<decltype(TED_DestroyClient)>::type;

using TED_CreateBreakpointReaderFncPtr = std::add_pointer<decltype(TED_CreateBreakpointReader)>::type;
using TED_DestroyBreakpointReaderFncPtr = std::add_pointer<decltype(TED_DestroyBreakpointReader)>::type;

using TED_GetBreakpointFncPtr = std::add_pointer<decltype(TED_GetBreakpoint)>::type;
using TED_DestroyBreakpointFncPtr = std::add_pointer<decltype(TED_DestroyBreakpoint)>::type;

using TED_GetModulesFncPtr = std::add_pointer<decltype(TED_GetModules)>::type;
using TED_DestroyModulesFncPtr = std::add_pointer<decltype(TED_DestroyModules)>::type;

using TED_EnableBreakAllCallsInModuleFncPtr = std::add_pointer<decltype(TED_EnableBreakAllCallsInModule)>::type;
using TED_DisableBreakAllCallsInModuleFncPtr = std::add_pointer<decltype(TED_DisableBreakAllCallsInModule)>::type;
using TED_EnableBreakCallByAddressFncPtr = std::add_pointer<decltype(TED_EnableBreakCallByAddress)>::type;
using TED_DisableBreakCallByAddressFncPtr = std::add_pointer<decltype(TED_DisableBreakCallByAddress)>::type;
using TED_EnableBreakCallByNameFncPtr = std::add_pointer<decltype(TED_EnableBreakCallByName)>::type;
using TED_DisableBreakCallByNameFncPtr = std::add_pointer<decltype(TED_DisableBreakCallByName)>::type;

using TED_EnableBreakpointByAddressFncPtr = std::add_pointer<decltype(TED_EnableBreakpointByAddress)>::type;
using TED_DisableBreakpointByAddressFncPtr = std::add_pointer<decltype(TED_DisableBreakpointByAddress)>::type;
using TED_EnableBreakpointByNameFncPtr = std::add_pointer<decltype(TED_EnableBreakpointByName)>::type;
using TED_DisableBreakpointByNameFncPtr = std::add_pointer<decltype(TED_DisableBreakpointByName)>::type;

using TED_DisassembleAddressFncPtr = std::add_pointer<decltype(TED_DisassembleAddress)>::type;
using TED_DestroyDisassembleAddressFncPtr = std::add_pointer<decltype(TED_DestroyDisassembleAddress)>::type;

using TED_LoadModuleFncPtr = std::add_pointer<decltype(TED_LoadModule)>::type;
using TED_UnloadModuleFncPtr = std::add_pointer<decltype(TED_UnloadModule)>::type;

using TED_ReadMemoryFncPtr = std::add_pointer<decltype(TED_ReadMemory)>::type;
using TED_DestroyReadMemoryFncPtr = std::add_pointer<decltype(TED_DestroyReadMemory)>::type;
using TED_WriteMemoryFncPtr = std::add_pointer<decltype(TED_WriteMemory)>::type;

using TED_CreateConsoleFncPtr = std::add_pointer<decltype(TED_CreateConsole)>::type;
using TED_DestroyConsoleFncPtr = std::add_pointer<decltype(TED_DestroyConsole)>::type;

using TED_EnableInternalLoggingFncPtr = std::add_pointer<decltype(TED_EnableInternalLogging)>::type;
using TED_DisableInternalLoggingFncPtr = std::add_pointer<decltype(TED_DisableInternalLogging)>::type;

using TED_SetOptionsFncPtr = std::add_pointer<decltype(TED_SetOptions)>::type;

using TED_TestFunctionFncPtr = std::add_pointer<decltype(TED_TestFunction)>::type;

using TED_DestroyGenericFncPtr = std::add_pointer<decltype(TED_DestroyGeneric)>::type;

using TED_CreateClientFncPtr = std::add_pointer<decltype(TED_CreateClient)>::type;
using TED_DestroyClientFncPtr = std::add_pointer<decltype(TED_DestroyClient)>::type;

using TED_GetBreakpointFncPtr = std::add_pointer<decltype(TED_GetBreakpoint)>::type;
using TED_DestroyBreakpointFncPtr = std::add_pointer<decltype(TED_DestroyBreakpoint)>::type;

using TED_GetModulesFncPtr = std::add_pointer<decltype(TED_GetModules)>::type;
using TED_DestroyModulesFncPtr = std::add_pointer<decltype(TED_DestroyModules)>::type;

inline TED_CreateClientFncPtr TED_CreateClientFnc{};
inline TED_DestroyClientFncPtr TED_DestroyClientFnc{};

inline TED_CreateBreakpointReaderFncPtr TED_CreateBreakpointReaderFnc{};
inline TED_DestroyBreakpointReaderFncPtr TED_DestroyBreakpointReaderFnc{};

inline TED_GetBreakpointFncPtr TED_GetBreakpointFnc{};
inline TED_DestroyBreakpointFncPtr TED_DestroyBreakpointFnc{};

inline TED_GetModulesFncPtr TED_GetModulesFnc{};
inline TED_DestroyModulesFncPtr TED_DestroyModulesFnc{};

inline TED_EnableBreakAllCallsInModuleFncPtr TED_EnableBreakAllCallsInModuleFnc{};
inline TED_DisableBreakAllCallsInModuleFncPtr TED_DisableBreakAllCallsInModuleFnc{};
inline TED_EnableBreakCallByAddressFncPtr TED_EnableBreakCallByAddressFnc{};
inline TED_DisableBreakCallByAddressFncPtr TED_DisableBreakCallByAddressFnc{};
inline TED_EnableBreakCallByNameFncPtr TED_EnableBreakCallByNameFnc{};
inline TED_DisableBreakCallByNameFncPtr TED_DisableBreakCallByNameFnc{};

inline TED_EnableBreakpointByAddressFncPtr TED_EnableBreakpointByAddressFnc{};
inline TED_DisableBreakpointByAddressFncPtr TED_DisableBreakpointByAddressFnc{};
inline TED_EnableBreakpointByNameFncPtr TED_EnableBreakpointByNameFnc{};
inline TED_DisableBreakpointByNameFncPtr TED_DisableBreakpointByNameFnc{};

inline TED_DisassembleAddressFncPtr TED_DisassembleAddressFnc{};
inline TED_DestroyDisassembleAddressFncPtr TED_DestroyDisassembleAddressFnc{};

inline TED_LoadModuleFncPtr TED_LoadModuleFnc{};
inline TED_UnloadModuleFncPtr TED_UnloadModuleFnc{};

inline TED_ReadMemoryFncPtr TED_ReadMemoryFnc{};
inline TED_DestroyReadMemoryFncPtr TED_DestroyReadMemoryFnc{};
inline TED_WriteMemoryFncPtr TED_WriteMemoryFnc{};

inline TED_CreateConsoleFncPtr TED_CreateConsoleFnc{};
inline TED_DestroyConsoleFncPtr TED_DestroyConsoleFnc{};

inline TED_EnableInternalLoggingFncPtr TED_EnableInternalLoggingFnc{};
inline TED_DisableInternalLoggingFncPtr TED_DisableInternalLoggingFnc{};

inline TED_SetOptionsFncPtr TED_SetOptionsFnc{};

inline TED_TestFunctionFncPtr TED_TestFunctionFnc{};

inline TED_DestroyGenericFncPtr TED_DestroyGenericFnc{};

typedef struct {
	unsigned long processId;
	char name[MAX_PATH];
	char path[MAX_PATH];
	char windowTitle[MAX_PATH];
} TED_ProcessInformation;

inline HMODULE TED_LoadClientAPI(const char* path)
{
	return LoadLibraryA(path);
}

inline void TED_ResolveClientFunctions(HMODULE moduleHandle)
{
	TED_CreateClientFnc = (TED_CreateClientFncPtr)GetProcAddress(moduleHandle, "TED_CreateClient");
	TED_DestroyClientFnc = (TED_DestroyClientFncPtr)GetProcAddress(moduleHandle, "TED_DestroyClient");

	TED_CreateBreakpointReaderFnc = (TED_CreateBreakpointReaderFncPtr)GetProcAddress(moduleHandle, "TED_CreateBreakpointReader");
	TED_DestroyBreakpointReaderFnc = (TED_DestroyBreakpointReaderFncPtr)GetProcAddress(moduleHandle, "TED_DestroyBreakpointReader");

	TED_GetBreakpointFnc = (TED_GetBreakpointFncPtr)GetProcAddress(moduleHandle, "TED_GetBreakpoint");
	TED_DestroyBreakpointFnc = (TED_DestroyBreakpointFncPtr)GetProcAddress(moduleHandle, "TED_DestroyBreakpoint");

	TED_GetModulesFnc = (TED_GetModulesFncPtr)GetProcAddress(moduleHandle, "TED_GetModules");
	TED_DestroyModulesFnc = (TED_DestroyModulesFncPtr)GetProcAddress(moduleHandle, "TED_DestroyModules");

	TED_EnableBreakAllCallsInModuleFnc = (TED_EnableBreakAllCallsInModuleFncPtr)GetProcAddress(moduleHandle, "TED_EnableBreakAllCallsInModule");
	TED_DisableBreakAllCallsInModuleFnc = (TED_DisableBreakAllCallsInModuleFncPtr)GetProcAddress(moduleHandle, "TED_DisableBreakAllCallsInModule");
	TED_EnableBreakCallByAddressFnc = (TED_EnableBreakCallByAddressFncPtr)GetProcAddress(moduleHandle, "TED_EnableBreakCallByAddress");
	TED_DisableBreakCallByAddressFnc = (TED_DisableBreakCallByAddressFncPtr)GetProcAddress(moduleHandle, "TED_DisableBreakCallByAddress");
	TED_EnableBreakCallByNameFnc = (TED_EnableBreakCallByNameFncPtr)GetProcAddress(moduleHandle, "TED_EnableBreakCallByName");
	TED_DisableBreakCallByNameFnc = (TED_DisableBreakCallByNameFncPtr)GetProcAddress(moduleHandle, "TED_DisableBreakCallByName");

	TED_EnableBreakpointByAddressFnc = (TED_EnableBreakpointByAddressFncPtr)GetProcAddress(moduleHandle, "TED_EnableBreakpointByAddress");
	TED_DisableBreakpointByAddressFnc = (TED_DisableBreakpointByAddressFncPtr)GetProcAddress(moduleHandle, "TED_DisableBreakpointByAddress");
	TED_EnableBreakpointByNameFnc = (TED_EnableBreakpointByNameFncPtr)GetProcAddress(moduleHandle, "TED_EnableBreakpointByName");
	TED_DisableBreakpointByNameFnc = (TED_DisableBreakpointByNameFncPtr)GetProcAddress(moduleHandle, "TED_DisableBreakpointByName");

	TED_DisassembleAddressFnc = (TED_DisassembleAddressFncPtr)GetProcAddress(moduleHandle, "TED_DisassembleAddress");
	TED_DestroyDisassembleAddressFnc = (TED_DestroyDisassembleAddressFncPtr)GetProcAddress(moduleHandle, "TED_DestroyDisassembleAddress");

	TED_LoadModuleFnc = (TED_LoadModuleFncPtr)GetProcAddress(moduleHandle, "TED_LoadModule");
	TED_UnloadModuleFnc = (TED_UnloadModuleFncPtr)GetProcAddress(moduleHandle, "TED_UnloadModule");

	TED_ReadMemoryFnc = (TED_ReadMemoryFncPtr)GetProcAddress(moduleHandle, "TED_ReadMemory");
	TED_DestroyReadMemoryFnc = (TED_DestroyReadMemoryFncPtr)GetProcAddress(moduleHandle, "TED_DestroyReadMemory");
	TED_WriteMemoryFnc = (TED_WriteMemoryFncPtr)GetProcAddress(moduleHandle, "TED_WriteMemory");

	TED_CreateConsoleFnc = (TED_CreateConsoleFncPtr)GetProcAddress(moduleHandle, "TED_CreateConsole");
	TED_DestroyConsoleFnc = (TED_DestroyConsoleFncPtr)GetProcAddress(moduleHandle, "TED_DestroyConsole");

	TED_EnableInternalLoggingFnc = (TED_EnableInternalLoggingFncPtr)GetProcAddress(moduleHandle, "TED_EnableInternalLogging");
	TED_DisableInternalLoggingFnc = (TED_DisableInternalLoggingFncPtr)GetProcAddress(moduleHandle, "TED_DisableInternalLogging");

	TED_SetOptionsFnc = (TED_SetOptionsFncPtr)GetProcAddress(moduleHandle, "TED_SetOptions");

	TED_TestFunctionFnc = (TED_TestFunctionFncPtr)GetProcAddress(moduleHandle, "TED_TestFunction");

	TED_DestroyGenericFnc = (TED_DestroyGenericFncPtr)GetProcAddress(moduleHandle, "TED_DestroyGeneric");
}

inline bool TED_InjectIntoProcess(unsigned long processId, const char* dllPath)
{
	auto processHandle{ OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
		| PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, processId) };
	if (processHandle == nullptr) {
		return false;
	}

	auto remoteDllPath{ VirtualAllocEx(processHandle, 0, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE) };
	if (remoteDllPath == 0) {
		return false;
	}

	auto written{ WriteProcessMemory(processHandle, remoteDllPath,
		dllPath, strlen(dllPath) + 1, 0) };
	if (!written) {
		return false;
	}

	FARPROC loadLibraryAddress = nullptr;

	int is32Bit{};
	IsWow64Process(processHandle, &is32Bit);
	if (is32Bit) {
		STARTUPINFOA startupInfo{};
		PROCESS_INFORMATION processInfo{};
		auto bridgeProcess{ CreateProcessA("tedx86injectorbridge.exe", nullptr, nullptr,
			nullptr, false, 0, nullptr, nullptr,
			&startupInfo, &processInfo) };
		if (bridgeProcess == 0) {
			return false;
		}
		
		WaitForSingleObject(processInfo.hProcess, 5000);
		unsigned long address = 0;
		GetExitCodeProcess(processInfo.hProcess, &address);
		if (address == 0) {
			return false;
		}

		loadLibraryAddress = reinterpret_cast<FARPROC>(address);

		CloseHandle(processInfo.hProcess);
		CloseHandle(processInfo.hThread);
	}
	else {
		loadLibraryAddress = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
	}

	if (loadLibraryAddress == nullptr) {
		return false;
	}

	auto remoteThread{ CreateRemoteThread(processHandle, 0, 0,
		reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibraryAddress), remoteDllPath, 0, 0) };
	if (remoteThread == nullptr) {
		return false;
	}

	WaitForSingleObject(remoteThread, INFINITE);

	VirtualFreeEx(processHandle, remoteDllPath, 0, MEM_RELEASE);

	return true;
}

inline TED_ProcessInformation** TED_GetActiveProcessesInformation(size_t* processCount)
{
	if (processCount == nullptr) {
		return nullptr;

	}

	std::array<unsigned long, 1024> processIds{};
	unsigned long bytesNeeded{};
	if (!EnumProcesses(processIds.data(), static_cast<unsigned long>(processIds.size() * sizeof(unsigned long)), &bytesNeeded)) {
		return nullptr;
	}

	*processCount = bytesNeeded / sizeof(unsigned long);
	if (processCount == 0) {
		return nullptr;
	}

	auto** processInformation{ new TED_ProcessInformation * [*processCount]{} };
	int processInformationIndex{};
	for (size_t i{ 0 }; i < *processCount; i++) {
		auto processHandle{ OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
		| PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, processIds[i]) };
		if (processHandle != nullptr) {

			unsigned long pathSize{ MAX_PATH };
			std::array<char, MAX_PATH> processPathArg{};
			QueryFullProcessImageNameA(processHandle, 0, processPathArg.data(), &pathSize);

			std::string processPath{ processPathArg.data(), pathSize };
			if (processPath.length() > 0) {

				std::string processName{ processPath.substr(processPath.find_last_of("\\") + 1) };
				processInformation[processInformationIndex] = new TED_ProcessInformation{};
				processInformation[processInformationIndex]->processId = processIds[i];
				strncpy_s(processInformation[processInformationIndex]->name, processName.c_str(), processName.length());
				strncpy_s(processInformation[processInformationIndex]->path, processPath.c_str(), processPath.length());
				auto arg{ std::make_pair(processIds[i], processInformation[processInformationIndex]) };
				EnumWindows([](HWND windowHandle, LPARAM arg) {

					auto enumArg{ reinterpret_cast<std::pair<unsigned long, TED_ProcessInformation*> *>(arg) };
					unsigned long processId{};
					GetWindowThreadProcessId(windowHandle, &processId);
					if (enumArg->first != processId)
					{
						return TRUE;
					}

					GetWindowTextA(windowHandle, enumArg->second->windowTitle, sizeof(enumArg->second->windowTitle));
					return FALSE;
					}, reinterpret_cast<LPARAM>(&arg));

				processInformationIndex++;
			}

			CloseHandle(processHandle);
		}
	}

	*processCount = processInformationIndex;

	return processInformation;
}

inline void TED_DestroyActiveProcessesInformation(TED_ProcessInformation** processInformation, size_t processCount)
{
	if (processInformation == 0) {
		return;
	}

	if (processCount > 0) {
		for (size_t i{ 0 }; i < processCount; i++) {
			delete processInformation[i];
		}
	}

	delete[] processInformation;
}

inline bool TED_TerminateProcess(unsigned long processId)
{
	auto processHandle{ OpenProcess(PROCESS_TERMINATE, FALSE, processId) };
	if (processHandle == nullptr) {
		return false;
	}

	auto result{ TerminateProcess(processHandle, 0) };

	result &= (WaitForSingleObject(processHandle, 5000) != WAIT_FAILED);

	CloseHandle(processHandle);

	return result;
}

using TED_InjectIntoProcessFncPtr = std::add_pointer<decltype(TED_InjectIntoProcess)>::type;
using TED_GetActiveProcessesInformationFncPtr = std::add_pointer<decltype(TED_GetActiveProcessesInformation)>::type;
using TED_DestroyActiveProcessesInformationFncPtr = std::add_pointer<decltype(TED_DestroyActiveProcessesInformation)>::type;
using TED_TerminateProcessFncPtr = std::add_pointer<decltype(TED_TerminateProcess)>::type;


inline TED_InjectIntoProcessFncPtr TED_InjectIntoProcessFnc = &TED_InjectIntoProcess;
inline TED_GetActiveProcessesInformationFncPtr TED_GetActiveProcessesInformationFnc = &TED_GetActiveProcessesInformation;
inline TED_DestroyActiveProcessesInformationFncPtr TED_DestroyActiveProcessesInformationFnc = &TED_DestroyActiveProcessesInformation;
inline TED_TerminateProcessFncPtr TED_TerminateProcessFnc = &TED_TerminateProcess;

}

#endif
