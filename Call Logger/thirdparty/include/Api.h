#pragma once

#ifndef TED_API_H
#define TED_API_H

#include <type_traits>

#include "Structures.h"

extern "C"
{

#define SYMBOL_MAX_PATH 255

typedef struct
{
	bool returnCallStack;
	bool returnContext;
	bool returnSymbolInfo;
	bool useInvasiveBreakpoints;
	bool unsafeMemoryMode;
	bool autoDisableBreakpointsMode;
	bool killProcessOnDisconnect;
	char symbolPath[SYMBOL_MAX_PATH];
} TED_Options;

__declspec(dllexport) TED_Client* TED_CreateClient(const char* uri);
__declspec(dllexport) void TED_DestroyClient(TED_Client* client);

__declspec(dllexport) TED_BreakpointReader* TED_CreateBreakpointReader(TED_Client* client);
__declspec(dllexport) void TED_DestroyBreakpointReader(TED_BreakpointReader* reader);

__declspec(dllexport) TED_BreakpointResponse* TED_GetBreakpoint(TED_Client* client, TED_BreakpointReader* reader);
__declspec(dllexport) void TED_DestroyBreakpoint(TED_BreakpointResponse* response);

__declspec(dllexport) TED_GetModulesResponse* TED_GetModules(TED_Client* client);
__declspec(dllexport) void TED_DestroyModules(TED_GetModulesResponse* response);

__declspec(dllexport) TED_GenericResponse* TED_EnableBreakAllCallsInModule(TED_Client* client, const char* name);
__declspec(dllexport) TED_GenericResponse* TED_DisableBreakAllCallsInModule(TED_Client* client, const char* name);
__declspec(dllexport) TED_GenericResponse* TED_EnableBreakCallByAddress(TED_Client* client, uint64_t address);
__declspec(dllexport) TED_GenericResponse* TED_DisableBreakCallByAddress(TED_Client* client, uint64_t address);
__declspec(dllexport) TED_GenericResponse* TED_EnableBreakCallByName(TED_Client* client, const char* name);
__declspec(dllexport) TED_GenericResponse* TED_DisableBreakCallByName(TED_Client* client, const char* name);

__declspec(dllexport) TED_GenericResponse* TED_EnableBreakpointByAddress(TED_Client* client, uint64_t address);
__declspec(dllexport) TED_GenericResponse* TED_DisableBreakpointByAddress(TED_Client* client, uint64_t address);
__declspec(dllexport) TED_GenericResponse* TED_EnableBreakpointByName(TED_Client* client, const char* name);
__declspec(dllexport) TED_GenericResponse* TED_DisableBreakpointByName(TED_Client* client, const char* name);

__declspec(dllexport) TED_DisassembleAddressResponse* TED_DisassembleAddress(TED_Client* client, uint64_t address, uint32_t size);
__declspec(dllexport) void TED_DestroyDisassembleAddress(TED_DisassembleAddressResponse* response);

__declspec(dllexport) TED_GenericResponse* TED_LoadModule(TED_Client* client, const char* path);
__declspec(dllexport) TED_GenericResponse* TED_UnloadModule(TED_Client* client, const char* path);

__declspec(dllexport) TED_ReadMemoryResponse* TED_ReadMemory(TED_Client* client, uint64_t address, uint32_t size);
__declspec(dllexport) void TED_DestroyReadMemory(TED_ReadMemoryResponse* response);
__declspec(dllexport) TED_GenericResponse* TED_WriteMemory(TED_Client* client, uint64_t address, const unsigned char* bytes, uint32_t size);

__declspec(dllexport) TED_GenericResponse* TED_CreateConsole(TED_Client* client);
__declspec(dllexport) TED_GenericResponse* TED_DestroyConsole(TED_Client* client);

__declspec(dllexport) TED_GenericResponse* TED_EnableInternalLogging(TED_Client* client);
__declspec(dllexport) TED_GenericResponse* TED_DisableInternalLogging(TED_Client* client);

__declspec(dllexport) TED_GenericResponse* TED_SetOptions(TED_Client* client, TED_Options* options);

__declspec(dllexport) TED_GenericResponse* TED_TestFunction(TED_Client* client);

__declspec(dllexport) void TED_DestroyGeneric(TED_GenericResponse* response);

}

#endif
