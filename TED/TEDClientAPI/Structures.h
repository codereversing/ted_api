#pragma once

#ifndef TED_STRUCTURES_H
#define TED_STRUCTURES_H

#include <cstdint>

#define MODULE_MAX_PATH 255

extern "C"
{

using TED_Client = void*;
using TED_BreakpointReader = void*;

typedef struct
{
	uint32_t cs;
	uint32_t ds;
	uint32_t es;
	uint32_t fs;
	uint32_t gs;
	uint32_t ss;
} TED_SegmentRegisters;

typedef struct
{
	uint64_t dr0;
	uint64_t dr1;
	uint64_t dr2;
	uint64_t dr3;
	uint64_t dr6;
	uint64_t dr7;
} TED_DebugRegisters;

typedef struct
{
	uint64_t rax;
	uint64_t rcx;
	uint64_t rdx;
	uint64_t rbx;
	uint64_t rsp;
	uint64_t rbp;
	uint64_t rsi;
	uint64_t rdi;
	uint64_t rip;
} TED_GeneralRegisters;

typedef struct
{
	uint64_t r8;
	uint64_t r9;
	uint64_t r10;
	uint64_t r11;
	uint64_t r12;
	uint64_t r13;
	uint64_t r14;
	uint64_t r15;
} TED_GeneralRegistersX64;

typedef struct
{
	TED_SegmentRegisters segmentRegisters;
	TED_DebugRegisters debugRegisters;
	TED_GeneralRegisters generalRegisters;
	TED_GeneralRegistersX64 generalRegistersx64;
	uint32_t processorFlags;
} TED_Context;

typedef struct
{
	char* functionName;
	size_t functionNameLength;
} TED_Symbols;

typedef struct
{
	uint64_t rip;
	uint64_t returnAddress;
	uint64_t framePointer;
	uint64_t stackPointer;
	uint64_t parameters[4];
	TED_Symbols symbols;
} TED_StackFrame;

typedef struct
{
	TED_StackFrame** stackFrames;
	size_t stackFramesCount;
} TED_CallStack;

typedef struct
{
	uint32_t processId;
	uint32_t threadId;
	uint64_t sourceAddress;
	uint64_t destinationAddress;

	TED_Context context;
	TED_CallStack callStack;
} TED_BreakpointResponse;

typedef struct
{
	char name[9];
	uint64_t address;
	uint64_t size;
} TED_ExecutableSection;

typedef struct
{
	char name[MODULE_MAX_PATH];
	uint64_t baseAddress;
	uint64_t size;
	TED_ExecutableSection** executableSections;
	size_t executableSectionCount;
} TED_ModuleInfo;

typedef struct
{
	TED_ModuleInfo** moduleInfo;
	size_t moduleInfoCount;
} TED_GetModulesResponse;

typedef struct
{
	unsigned char* bytes;
	size_t bytesCount;
} TED_ReadMemoryResponse;

typedef struct
{
	uint64_t address;
	char mnemonic[32];
	char text[64];
	unsigned char bytes[32];
	size_t bytesCount;
} TED_Instruction;

typedef struct
{
	TED_Instruction** instructions;
	size_t instructionsCount;
} TED_DisassembleAddressResponse;

typedef struct
{
	bool success;
	unsigned int* errorCodes;
	size_t errorCodesCount;
	char** errorMessages;
	size_t errorMessagesCount;
} TED_GenericResponse;

}

#endif
