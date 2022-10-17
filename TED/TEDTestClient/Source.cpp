#pragma comment(lib, "Ws2_32.lib")

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "iphlpapi.lib")

#define WIN32_LEAN_AND_MEAN

#include <chrono>
#include <format>
#include <thread>

#include <Windows.h>

#include <grpcpp/channel.h>
#include <grpcpp/client_context.h>
#include <grpcpp/create_channel.h>

#include <grpc/grpc.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>

#include "Api.h"
#include "Structures.h"
#include "TEDClientBridge.h"

#include "Breakpoint.h"
#include "GrpcServer.h"

#include "Proto/TED.grpc.pb.h"



void TestGetModules(TED_Client* client)
{
	auto response{ TED_GetModules(client) };

	for (size_t i{ 0 }; i < response->moduleInfoCount; i++) {
		const auto* moduleInfo{ response->moduleInfo[i] };
		std::cout << std::format("Module name: {}\tModule base address: {:X}\tModule size: {:X}",
			moduleInfo->name,
			moduleInfo->baseAddress,
			moduleInfo->size)
			<< std::endl;

		for (size_t j{ 0 }; j < moduleInfo->executableSectionCount; j++) {
			const auto* executableSection{ response->moduleInfo[i]->executableSections[j] };
			std::cout << std::format("Section: {}\tSection base address: {:X}\tSection size: {:X}",
				executableSection->name,
				executableSection->address,
				executableSection->size)
				<< std::endl;
		}
	}

	TED_DestroyModules(response);
}

void TestEnableBreakAllCallsInModule(TED_Client* client)
{
	auto response{ TED_EnableBreakAllCallsInModule(client, "C:\\WINDOWS\\System32\\USER32.dll") };
	std::cout << "Success: " << response->success << std::endl;

	TED_DestroyGeneric(response);
}

void TestDisableBreakAllCallsInModule(TED_Client* client)
{
	auto response{ TED_DisableBreakAllCallsInModule(client, "C:\\WINDOWS\\System32\\USER32.dll") };
	std::cout << "Success: " << response->success << std::endl;

	TED_DestroyGeneric(response);
}

void TestEnableBreakCallByAddress(TED_Client* client)
{
	auto response{ TED_EnableBreakCallByAddress(client, (uint64_t)MessageBoxA) };
	std::cout << "Success: " << response->success << std::endl;

	TED_DestroyGeneric(response);
}

void TestDisableBreakCallByAddress(TED_Client* client)
{
	auto response{ TED_DisableBreakCallByAddress(client, (uint64_t)MessageBoxA) };
	std::cout << "Success: " << response->success << std::endl;

	TED_DestroyGeneric(response);
}

void TestEnableBreakCallByName(TED_Client* client)
{
	auto response{ TED_EnableBreakCallByName(client, "IsCharLowerA") };
	std::cout << "Success: " << response->success << std::endl;

	TED_DestroyGeneric(response);
}

void TestDisableBreakCallByName(TED_Client* client)
{
	auto response{ TED_DisableBreakCallByName(client, "IsCharLowerA") };
	std::cout << "Success: " << response->success << std::endl;

	TED_DestroyGeneric(response);
}

void TestEnableBreakpointByAddress(TED_Client* client)
{
	auto response{ TED_EnableBreakpointByAddress(client, (uint64_t)MessageBoxA) };
	std::cout << "Success: " << response->success << std::endl;

	TED_DestroyGeneric(response);
}

void TestDisableBreakpointByAddress(TED_Client* client)
{
	auto response{ TED_DisableBreakpointByAddress(client, (uint64_t)MessageBoxA) };
	std::cout << "Success: " << response->success << std::endl;

	TED_DestroyGeneric(response);
}

void TestEnableBreakpointByName(TED_Client* client)
{
	auto response{ TED_EnableBreakpointByName(client, "IsCharLowerA") };
	std::cout << "Success: " << response->success << std::endl;

	TED_DestroyGeneric(response);
}

void TestDisableBreakpointByName(TED_Client* client)
{
	auto response{ TED_DisableBreakpointByName(client, "IsCharLowerA") };
	std::cout << "Success: " << response->success << std::endl;

	TED_DestroyGeneric(response);
}

void TestDisassemble(TED_Client* client)
{
	auto response{ TED_DisassembleAddress(client, (uint64_t)MessageBoxA, 40) };

	for (size_t i{ 0 }; i < response->instructionsCount; i++) {
		const auto* instruction = response->instructions[i];
		std::cout << std::format("0x{:X} ",
			instruction->address);

		for (size_t j{ 0 }; j < instruction->bytesCount; j++) {
			std::cout << std::format("{:x} ",
				(unsigned char)instruction->bytes[j]);
		}

		std::cout << std::format("{} {}",
			instruction->mnemonic,
			instruction->text)
			<< std::endl;
	}

	TED_DestroyDisassembleAddress(response);
}

void TestLoadModule(TED_Client* client)
{
	auto response{ TED_LoadModule(client, "C:\\WINDOWS\\System32\\midimap.dll") };
	std::cout << "Success: " << response->success << std::endl;

	TED_DestroyGeneric(response);
}

void TestUnloadModule(TED_Client* client)
{
	auto response{ TED_UnloadModule(client, "C:\\WINDOWS\\System32\\midimap.dll") };
	std::cout << "Success: " << response->success << std::endl;

	TED_DestroyGeneric(response);
}

void TestReadMemory(TED_Client* client)
{
	auto response{ TED_ReadMemory(client, (uint64_t)MessageBoxA, 15) };
	for (size_t i{ 0 }; i < response->bytesCount; i++) {
		std::cout << std::format("{:x} ",
			(unsigned char)response->bytes[i]);
	}

	std::cout << std::endl;

	TED_DestroyReadMemory(response);
}

void TestWriteMemory(TED_Client* client, unsigned char byte)
{
	auto response{ TED_WriteMemory(client, (uint64_t)MessageBoxA, &byte, 1) };
	std::cout << "Success: " << response->success << std::endl;

	TED_DestroyGeneric(response);
}

void TestOptions(TED_Client* client)
{
	TED_Options options{};
	options.returnCallStack = true;
	options.returnContext = true;
	options.returnSymbolInfo = true;

	auto response{ TED_SetOptions(client, &options) };

	TED_DestroyGeneric(response);
}

void TestCreateConsole(TED_Client* client)
{
	auto response{ TED_CreateConsole(client) };
	std::cout << "Success: " << response->success << std::endl;

	TED_DestroyGeneric(response);
}

void TestDestroyConsole(TED_Client* client)
{
	auto response{ TED_DestroyConsole(client) };
	std::cout << "Success: " << response->success << std::endl;

	TED_DestroyGeneric(response);
}

void TestEnableLogging(TED_Client* client)
{
	auto response{ TED_EnableInternalLogging(client) };
	std::cout << "Success: " << response->success << std::endl;

	TED_DestroyGeneric(response);
}

void TestDisableLogging(TED_Client* client)
{
	auto response{ TED_DisableInternalLogging(client) };
	std::cout << "Success: " << response->success << std::endl;

	TED_DestroyGeneric(response);
}

void TestFunction(TED_Client* client)
{
	auto response{ TED_TestFunction(client) };
	std::cout << "Success: " << response->success << std::endl;

	TED_DestroyGeneric(response);
}

void TestGetBreakpoints(TED_Client* client, TED_BreakpointReader* reader)
{
	auto response{ TED_GetBreakpoint(client, reader) };
	if (response != nullptr) {

		std::cout << "Read breakpoint event\t"
			<< std::format("Process ID: {}\tThread ID: {}\tSource Address: {:X}\tDestination Address: {:X}",
				response->processId, response->threadId, response->sourceAddress, response->destinationAddress)
			<< std::endl;

		std::cout << "Context: \n"
			<< std::format("RAX:{:X} RBX:{:X} RCX:{:X} RDX:{:X}",
				response->context.generalRegisters.rax,
				response->context.generalRegisters.rbx,
				response->context.generalRegisters.rcx,
				response->context.generalRegisters.rdx)
			<< std::format(" RSP:{:X} RBP:{:X} RSI:{:X} RDI:{:X}",
				response->context.generalRegisters.rsp,
				response->context.generalRegisters.rbp,
				response->context.generalRegisters.rsi,
				response->context.generalRegisters.rdi)
			<< std::format(" RIP:{:X}",
				response->context.generalRegisters.rip)
			<< std::format(" R8:{:X} R9:{:X} R10:{:X} R11:{:X}",
				response->context.generalRegistersx64.r8,
				response->context.generalRegistersx64.r9,
				response->context.generalRegistersx64.r10,
				response->context.generalRegistersx64.r11)
			<< std::format(" R12:{:X} R13:{:X} R14:{:X} R15:{:X}",
				response->context.generalRegistersx64.r12,
				response->context.generalRegistersx64.r13,
				response->context.generalRegistersx64.r14,
				response->context.generalRegistersx64.r15)
			<< std::format(" DR0:{:X} DR1:{:X} DR2:{:X} DR3:{:X}",
				response->context.debugRegisters.dr0,
				response->context.debugRegisters.dr1,
				response->context.debugRegisters.dr2,
				response->context.debugRegisters.dr3)
			<< std::format(" DR6:{:X} DR7:{:X}",
				response->context.debugRegisters.dr6,
				response->context.debugRegisters.dr7)
			<< std::format(" CS:{:X} DS:{:X} ES:{:X} FS:{:X}",
				response->context.segmentRegisters.cs,
				response->context.segmentRegisters.ds,
				response->context.segmentRegisters.es,
				response->context.segmentRegisters.fs)
			<< std::format(" GS:{:X} SS:{:X}",
				response->context.segmentRegisters.gs,
				response->context.segmentRegisters.ss)
			<< std::endl;

		std::cout << "Call stack: \n";
		if (response->callStack.stackFramesCount > 0) {
			for (size_t i{ 0 }; i < response->callStack.stackFramesCount; i++) {
				const auto* stackFrame = response->callStack.stackFrames[i];
				std::cout
					<< std::format("RIP:{:X} Return Address:{:X} Frame Pointer:{:X} Stack Pointer:{:X}",
						stackFrame->rip,
						stackFrame->returnAddress,
						stackFrame->framePointer,
						stackFrame->stackPointer)
					<< std::format(" Param 1:{:X} Param 2:{:X} Param 3:{:X} Param 4:{:X}",
						stackFrame->parameters[0],
						stackFrame->parameters[1],
						stackFrame->parameters[2],
						stackFrame->parameters[3]);
				if (stackFrame->symbols.functionNameLength > 0) {
					std::cout << " " << stackFrame->symbols.functionName;
				}

				std::cout << std::endl;
			}
		}
	}

	TED_DestroyBreakpoint(response);
}

void StartGrpcServer() {
	std::thread([]() {
		std::string server_address("0.0.0.0:50051");
		TED::Communication::TEDServiceImpl service(GetCurrentThreadId());

		grpc::ServerBuilder builder;
		builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
		builder.RegisterService(&service);
		std::unique_ptr<grpc::Server> server = std::move(builder.BuildAndStart());

		server->Wait();
		}).detach();
}

int main(int argc, char* argv[])
{
	AddVectoredExceptionHandler(0x1, TED::Breakpoint::BreakpointHandler);

	StartGrpcServer();

	size_t count{};
	auto processes{ TED_GetActiveProcessesInformation(&count) };
	for (size_t i{ 0 }; i < count; i++) {
		const auto& process = processes[i];
		std::cout << process->processId << " "
			<< process->name << " "
			<< process->windowTitle << " "
			<< process->path
			<< std::endl;
	}

	TED_DestroyActiveProcessesInformation(processes, count);

	auto client{ TED_CreateClient("localhost:50051") };

	TestGetModules(client);
	TestOptions(client);
	TestEnableBreakAllCallsInModule(client);
	TestDisableBreakAllCallsInModule(client);
	TestEnableBreakCallByAddress(client);
	TestDisableBreakCallByAddress(client);
	TestEnableBreakCallByName(client);
	TestDisableBreakCallByName(client);

	TestDisassemble(client);

	TestEnableBreakpointByAddress(client);
	TestDisableBreakpointByAddress(client);
	TestEnableBreakpointByName(client);
	TestDisableBreakpointByName(client);

	TestLoadModule(client);
	TestUnloadModule(client);

	TestWriteMemory(client, 0xCC);
	TestReadMemory(client);
	TestWriteMemory(client, 0x48);
	TestReadMemory(client);

	TestCreateConsole(client);

	TestEnableLogging(client);

	TestFunction(client);
	TestFunction(client);

	TestDisableLogging(client);
	TestDestroyConsole(client);

	auto* reader{ TED_CreateBreakpointReader(client) };

	while (true) {
		TestGetBreakpoints(client, reader);
	}

	TED_DestroyBreakpointReader(reader);
	TED_DestroyClient(client);

	std::cout << "Done!" << std::endl;

	return 0;
}
