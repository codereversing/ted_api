#pragma comment(lib, "Ws2_32.lib")

#include "Api.h"

#include <grpcpp/channel.h>
#include <grpcpp/client_context.h>
#include <grpcpp/create_channel.h>

#include "Proto/TED.pb.h"
#include "Proto/TED.grpc.pb.h"

typedef struct {
	grpc::ClientContext context;
	TED_BreakpointReader* reader;

} TED_BreakpointReaderInternal;

__declspec(dllexport) TED_Client* TED_CreateClient(const char* uri)
{
	if (uri == nullptr) {
		return nullptr;
	}

	auto channel{ grpc::CreateChannel(uri,
		grpc::InsecureChannelCredentials()) };
	return reinterpret_cast<TED_Client*>(TED::Grpc::TEDService::NewStub(channel).release());
}

__declspec(dllexport) void TED_DestroyClient(TED_Client* client)
{
	if (client != nullptr) {
		auto* stub{ reinterpret_cast<TED::Grpc::TEDService::Stub*>(client) };

		delete stub;
		client = nullptr;
	}
}

__declspec(dllexport) TED_BreakpointReader* TED_CreateBreakpointReader(TED_Client* client)
{
	if (client == nullptr) {
		return nullptr;
	}

	auto* stub{ reinterpret_cast<TED::Grpc::TEDService::Stub*>(client) };

	auto* reader = new TED_BreakpointReaderInternal{};
	reader->reader = reinterpret_cast<TED_BreakpointReader*>(
		stub->GetBreakpoints(&reader->context, TED::Grpc::Empty{}).release());

	return reinterpret_cast<TED_BreakpointReader*>(reader);
}

__declspec(dllexport) void TED_DestroyBreakpointReader(TED_BreakpointReader* reader)
{
	if (reader != nullptr) {
		TED_BreakpointReaderInternal* internalReader = reinterpret_cast<TED_BreakpointReaderInternal*>(reader);

		auto* underlyingReader{
			reinterpret_cast<grpc::ClientReader<TED::Grpc::BreakpointResponse> *>(internalReader->reader) };

		underlyingReader->Finish();

		delete internalReader->reader;
		internalReader->reader = nullptr;

		delete internalReader;
	}
}

__declspec(dllexport) TED_BreakpointResponse* TED_GetBreakpoint(TED_Client* client, TED_BreakpointReader* reader)
{
	if (client == nullptr || reader == nullptr) {
		return nullptr;
	}

	auto* stub{ reinterpret_cast<TED::Grpc::TEDService::Stub*>(client) };
	TED_BreakpointReaderInternal* internalReader = reinterpret_cast<TED_BreakpointReaderInternal*>(reader);

	auto underlyingReader{
		reinterpret_cast<grpc::ClientReader<TED::Grpc::BreakpointResponse>*>(internalReader->reader) };

	auto* apiResponse{ new TED_BreakpointResponse{} };
	TED::Grpc::BreakpointResponse response{};
	if (underlyingReader->Read(&response)) {
		apiResponse->processId = response.process_id();
		apiResponse->threadId = response.thread_id();
		apiResponse->sourceAddress = response.source_address();
		apiResponse->destinationAddress = response.destination_address();
		if (response.has_context()) {
			apiResponse->context.generalRegisters.rax = response.context().general_registers().rax();
			apiResponse->context.generalRegisters.rbx = response.context().general_registers().rbx();
			apiResponse->context.generalRegisters.rcx = response.context().general_registers().rcx();
			apiResponse->context.generalRegisters.rdx = response.context().general_registers().rdx();
			apiResponse->context.generalRegisters.rsp = response.context().general_registers().rsp();
			apiResponse->context.generalRegisters.rbp = response.context().general_registers().rbp();
			apiResponse->context.generalRegisters.rsi = response.context().general_registers().rsi();
			apiResponse->context.generalRegisters.rdi = response.context().general_registers().rdi();
			apiResponse->context.generalRegisters.rip = response.context().general_registers().rip();

			apiResponse->context.generalRegistersx64.r8 = response.context().general_registers_x64().r8();
			apiResponse->context.generalRegistersx64.r9 = response.context().general_registers_x64().r9();
			apiResponse->context.generalRegistersx64.r10 = response.context().general_registers_x64().r10();
			apiResponse->context.generalRegistersx64.r11 = response.context().general_registers_x64().r11();
			apiResponse->context.generalRegistersx64.r12 = response.context().general_registers_x64().r12();
			apiResponse->context.generalRegistersx64.r13 = response.context().general_registers_x64().r13();
			apiResponse->context.generalRegistersx64.r14 = response.context().general_registers_x64().r14();
			apiResponse->context.generalRegistersx64.r15 = response.context().general_registers_x64().r15();

			apiResponse->context.debugRegisters.dr0 = response.context().debug_registers().dr0();
			apiResponse->context.debugRegisters.dr1 = response.context().debug_registers().dr1();
			apiResponse->context.debugRegisters.dr2 = response.context().debug_registers().dr2();
			apiResponse->context.debugRegisters.dr3 = response.context().debug_registers().dr3();
			apiResponse->context.debugRegisters.dr6 = response.context().debug_registers().dr6();
			apiResponse->context.debugRegisters.dr7 = response.context().debug_registers().dr7();

			apiResponse->context.segmentRegisters.cs = response.context().segment_registers().cs();
			apiResponse->context.segmentRegisters.ds = response.context().segment_registers().ds();
			apiResponse->context.segmentRegisters.es = response.context().segment_registers().es();
			apiResponse->context.segmentRegisters.fs = response.context().segment_registers().fs();
			apiResponse->context.segmentRegisters.gs = response.context().segment_registers().gs();
			apiResponse->context.segmentRegisters.ss = response.context().segment_registers().ss();

			apiResponse->context.processorFlags = response.context().processor_flags();
		}

		if (response.has_call_stack()) {
			apiResponse->callStack.stackFrames = new TED_StackFrame * [response.call_stack().stack_frame_size()]{};
			apiResponse->callStack.stackFramesCount = response.call_stack().stack_frame_size();
			for (auto i{ 0 }; i < response.call_stack().stack_frame_size(); i++) {
				apiResponse->callStack.stackFrames[i] = new TED_StackFrame{};
				apiResponse->callStack.stackFrames[i]->framePointer = response.call_stack().stack_frame(i).frame_pointer();
				apiResponse->callStack.stackFrames[i]->stackPointer = response.call_stack().stack_frame(i).stack_pointer();
				apiResponse->callStack.stackFrames[i]->rip = response.call_stack().stack_frame(i).rip();
				apiResponse->callStack.stackFrames[i]->returnAddress = response.call_stack().stack_frame(i).return_address();
				std::memcpy(&apiResponse->callStack.stackFrames[i]->parameters, response.call_stack().stack_frame(i).parameters().data(),
					sizeof(apiResponse->callStack.stackFrames[i]->parameters));
				if (response.call_stack().stack_frame(i).has_symbols()) {
					apiResponse->callStack.stackFrames[i]->symbols.functionNameLength =
						response.call_stack().stack_frame(i).symbols().function_name().length();
					apiResponse->callStack.stackFrames[i]->symbols.functionName =
						new char[response.call_stack().stack_frame(i).symbols().function_name().length() + 1]{};
					strncpy_s(apiResponse->callStack.stackFrames[i]->symbols.functionName,
						response.call_stack().stack_frame(i).symbols().function_name().length() + 1,
						response.call_stack().stack_frame(i).symbols().function_name().c_str(),
						response.call_stack().stack_frame(i).symbols().function_name().length());
				}
			}
		}

		return apiResponse;
	}

	return nullptr;
}

__declspec(dllexport) void TED_DestroyBreakpoint(TED_BreakpointResponse* response)
{
	if (response == nullptr) {
		return;
	}

	if (response->callStack.stackFramesCount > 0) {
		for (size_t i{ 0 }; i < response->callStack.stackFramesCount; i++) {
			auto& symbols{ response->callStack.stackFrames[i]->symbols };
			if (symbols.functionNameLength > 0) {
				delete symbols.functionName;
				symbols.functionName = nullptr;
			}
		}
		delete[] response->callStack.stackFrames;
		response->callStack.stackFrames = nullptr;
	}

	delete response;
	response = nullptr;
}

__declspec(dllexport) TED_GetModulesResponse* TED_GetModules(TED_Client* client)
{
	if (client == nullptr) {
		return nullptr;
	}

	auto* stub{ reinterpret_cast<TED::Grpc::TEDService::Stub*>(client) };

	grpc::ClientContext context{};
	TED::Grpc::GetModulesResponse response{};
	auto result{ stub->GetModules(&context, TED::Grpc::Empty{}, &response) };
	if (!result.ok()) {
		return nullptr;
	}

	if (response.module_info_size() > 0) {
		auto* apiResponse{ new TED_GetModulesResponse{} };
		apiResponse->moduleInfo = new TED_ModuleInfo * [response.module_info_size()]{};
		apiResponse->moduleInfoCount = response.module_info_size();

		for (auto i{ 0 }; i < response.module_info_size(); i++) {
			apiResponse->moduleInfo[i] = new TED_ModuleInfo{};
			auto moduleInfo{ response.module_info(i) };
			apiResponse->moduleInfo[i]->baseAddress = moduleInfo.base_address();
			strncpy_s(apiResponse->moduleInfo[i]->name, moduleInfo.name().c_str(), sizeof(TED_ModuleInfo::name));
			apiResponse->moduleInfo[i]->size = moduleInfo.size();
			if (moduleInfo.executable_sections_size() > 0) {
				apiResponse->moduleInfo[i]->executableSections = new TED_ExecutableSection * [moduleInfo.executable_sections_size()]{};
				apiResponse->moduleInfo[i]->executableSectionCount = moduleInfo.executable_sections_size();
				for (auto j{ 0 }; j < moduleInfo.executable_sections_size(); j++) {
					apiResponse->moduleInfo[i]->executableSections[j] = new TED_ExecutableSection{};
					apiResponse->moduleInfo[i]->executableSections[j]->address = moduleInfo.executable_sections(j).address();
					strncpy_s(apiResponse->moduleInfo[i]->executableSections[j]->name,
						moduleInfo.executable_sections(j).name().c_str(), sizeof(TED_ExecutableSection::name));
					apiResponse->moduleInfo[i]->executableSections[j]->size = moduleInfo.executable_sections(j).size();
				}
			}

		}

		return apiResponse;
	}

	return nullptr;
}

__declspec(dllexport) void TED_DestroyModules(TED_GetModulesResponse* response)
{
	if (response == nullptr) {
		return;
	}

	if (response->moduleInfoCount > 0) {
		for (size_t i{ 0 }; i < response->moduleInfoCount; i++) {
			auto* moduleInfo{ response->moduleInfo[i] };
			if (moduleInfo->executableSectionCount > 0) {
				for (size_t j{ 0 }; j < moduleInfo->executableSectionCount; j++) {
					delete moduleInfo->executableSections[j];
					moduleInfo->executableSections[j] = nullptr;
				}

				delete[] moduleInfo->executableSections;
				moduleInfo->executableSections = nullptr;
			}

			delete moduleInfo;
			moduleInfo = nullptr;
		}

		delete[] response->moduleInfo;
		response->moduleInfo = nullptr;
	}

	delete response;
	response = nullptr;
}

TED_GenericResponse* BuildGenericResponse(TED::Grpc::GenericResponse& response)
{
	auto* apiResponse{ new TED_GenericResponse{} };

	apiResponse->success = response.success();
	if (response.error_message_size() > 0) {
		apiResponse->errorCodesCount = response.error_message_size();
		apiResponse->errorMessages = new char* [response.error_message_size()];
		for (auto i{ 0 }; i < response.error_message_size(); i++) {
			apiResponse->errorMessages[i] = new char[response.error_message(i).length() + 1]{};
			strncpy_s(apiResponse->errorMessages[i], response.error_message(i).length(),
				response.error_message(i).c_str(), response.error_message(i).length());
		}
	}

	if (response.last_error_code_size() > 0) {
		apiResponse->errorCodesCount = response.last_error_code_size();
		apiResponse->errorCodes = new unsigned int[response.last_error_code_size()];
		for (auto i{ 0 }; i < response.last_error_code_size(); i++) {
			apiResponse->errorCodes[i] = response.last_error_code(i);
		}
	}

	return apiResponse;
}

__declspec(dllexport) TED_GenericResponse* TED_EnableBreakAllCallsInModule(TED_Client* client, const char* name)
{
	if (client == nullptr || name == nullptr) {
		return nullptr;
	}

	auto* stub{ reinterpret_cast<TED::Grpc::TEDService::Stub*>(client) };

	grpc::ClientContext context{};
	TED::Grpc::EnableBreakAllCallsInModuleRequest request{};
	request.set_module_name(name);

	TED::Grpc::GenericResponse response{};
	auto result{ stub->EnableBreakAllCallsInModule(&context, request, &response) };
	if (!result.ok()) {
		return nullptr;
	}

	return BuildGenericResponse(response);
}

__declspec(dllexport) TED_GenericResponse* TED_DisableBreakAllCallsInModule(TED_Client* client, const char* name)
{
	if (client == nullptr || name == nullptr) {
		return nullptr;
	}

	auto* stub{ reinterpret_cast<TED::Grpc::TEDService::Stub*>(client) };

	grpc::ClientContext context{};
	TED::Grpc::DisableBreakAllCallsInModuleRequest request{};
	request.set_module_name(name);

	TED::Grpc::GenericResponse response{};
	auto result{ stub->DisableBreakAllCallsInModule(&context, request, &response) };
	if (!result.ok()) {
		return nullptr;
	}

	return BuildGenericResponse(response);
}

__declspec(dllexport) TED_GenericResponse* TED_EnableBreakCallByAddress(TED_Client* client, uint64_t address)
{
	if (client == nullptr) {
		return nullptr;
	}

	auto* stub{ reinterpret_cast<TED::Grpc::TEDService::Stub*>(client) };

	grpc::ClientContext context{};
	TED::Grpc::EnableBreakCallByAddressRequest request{};
	request.set_address(address);

	TED::Grpc::GenericResponse response{};
	auto result{ stub->EnableBreakCallByAddress(&context, request, &response) };
	if (!result.ok()) {
		return nullptr;
	}

	return BuildGenericResponse(response);
}

__declspec(dllexport) TED_GenericResponse* TED_DisableBreakCallByAddress(TED_Client* client, uint64_t address)
{
	if (client == nullptr) {
		return nullptr;
	}

	auto* stub{ reinterpret_cast<TED::Grpc::TEDService::Stub*>(client) };

	grpc::ClientContext context{};
	TED::Grpc::DisableBreakCallByAddressRequest request{};
	request.set_address(address);

	TED::Grpc::GenericResponse response{};
	auto result{ stub->DisableBreakCallByAddress(&context, request, &response) };
	if (!result.ok()) {
		return nullptr;
	}

	return BuildGenericResponse(response);
}

__declspec(dllexport) TED_GenericResponse* TED_EnableBreakCallByName(TED_Client* client, const char* name)
{
	if (client == nullptr || name == nullptr) {
		return nullptr;
	}

	auto* stub{ reinterpret_cast<TED::Grpc::TEDService::Stub*>(client) };

	grpc::ClientContext context{};
	TED::Grpc::EnableBreakCallByNameRequest request{};
	request.set_name(name);

	TED::Grpc::GenericResponse response{};
	auto result{ stub->EnableBreakCallByName(&context, request, &response) };
	if (!result.ok()) {
		return nullptr;
	}

	return BuildGenericResponse(response);
}

__declspec(dllexport) TED_GenericResponse* TED_DisableBreakCallByName(TED_Client* client, const char* name)
{
	if (client == nullptr || name == nullptr) {
		return nullptr;
	}

	auto* stub{ reinterpret_cast<TED::Grpc::TEDService::Stub*>(client) };

	grpc::ClientContext context{};
	TED::Grpc::DisableBreakCallByNameRequest request{};
	request.set_name(name);

	TED::Grpc::GenericResponse response{};
	auto result{ stub->DisableBreakCallByName(&context, request, &response) };
	if (!result.ok()) {
		return nullptr;
	}

	return BuildGenericResponse(response);
}

__declspec(dllexport) TED_GenericResponse* TED_EnableBreakpointByAddress(TED_Client* client, uint64_t address)
{
	if (client == nullptr) {
		return nullptr;
	}

	auto* stub{ reinterpret_cast<TED::Grpc::TEDService::Stub*>(client) };

	grpc::ClientContext context{};
	TED::Grpc::EnableBreakpointByAddressRequest request{};
	request.set_address(address);

	TED::Grpc::GenericResponse response{};
	auto result{ stub->EnableBreakpointByAddress(&context, request, &response) };
	if (!result.ok()) {
		return nullptr;
	}

	return BuildGenericResponse(response);
}

__declspec(dllexport) TED_GenericResponse* TED_DisableBreakpointByAddress(TED_Client* client, uint64_t address)
{
	if (client == nullptr) {
		return nullptr;
	}

	auto* stub{ reinterpret_cast<TED::Grpc::TEDService::Stub*>(client) };

	grpc::ClientContext context{};
	TED::Grpc::DisableBreakpointByAddressRequest request{};
	request.set_address(address);

	TED::Grpc::GenericResponse response{};
	auto result{ stub->DisableBreakpointByAddress(&context, request, &response) };
	if (!result.ok()) {
		return nullptr;
	}

	return BuildGenericResponse(response);
}

__declspec(dllexport) TED_GenericResponse* TED_EnableBreakpointByName(TED_Client* client, const char* name)
{
	if (client == nullptr || name == nullptr) {
		return nullptr;
	}

	auto* stub{ reinterpret_cast<TED::Grpc::TEDService::Stub*>(client) };

	grpc::ClientContext context{};
	TED::Grpc::EnableBreakpointByNameRequest request{};
	request.set_name(name);

	TED::Grpc::GenericResponse response{};
	auto result{ stub->EnableBreakpointByName(&context, request, &response) };
	if (!result.ok()) {
		return nullptr;
	}

	return BuildGenericResponse(response);
}

__declspec(dllexport) TED_GenericResponse* TED_DisableBreakpointByName(TED_Client* client, const char* name)
{
	if (client == nullptr || name == nullptr) {
		return nullptr;
	}

	auto* stub{ reinterpret_cast<TED::Grpc::TEDService::Stub*>(client) };

	grpc::ClientContext context{};
	TED::Grpc::DisableBreakpointByNameRequest request{};
	request.set_name(name);

	TED::Grpc::GenericResponse response{};
	auto result{ stub->DisableBreakpointByName(&context, request, &response) };
	if (!result.ok()) {
		return nullptr;
	}

	return BuildGenericResponse(response);
}

__declspec(dllexport) TED_DisassembleAddressResponse* TED_DisassembleAddress(TED_Client* client, uint64_t address, uint32_t size)
{
	if (client == nullptr) {
		return nullptr;
	}

	auto* stub{ reinterpret_cast<TED::Grpc::TEDService::Stub*>(client) };

	grpc::ClientContext context{};
	TED::Grpc::DisassembleAddressRequest request{};
	request.set_address(address);
	request.set_size(size);

	TED::Grpc::DisassembleAddressResponse response{};
	auto result{ stub->DisassembleAddress(&context, request, &response) };
	if (!result.ok()) {
		return nullptr;
	}

	if (response.instructions_size() > 0) {
		auto* apiResponse{ new TED_DisassembleAddressResponse{} };
		apiResponse->instructions = new TED_Instruction * [response.instructions_size()]{};
		apiResponse->instructionsCount = response.instructions_size();
		for (auto i{ 0 }; i < response.instructions_size(); i++) {
			apiResponse->instructions[i] = new TED_Instruction{};
			apiResponse->instructions[i]->address = response.instructions(i).address();
			memcpy(apiResponse->instructions[i]->bytes, response.instructions(i).bytes().c_str(),
				response.instructions(i).bytes().size());
			apiResponse->instructions[i]->bytesCount = response.instructions(i).bytes().size();
			strncpy_s(apiResponse->instructions[i]->mnemonic,
				response.instructions(i).mnemonic().data(), response.instructions(i).mnemonic().length());
			strncpy_s(apiResponse->instructions[i]->text,
				response.instructions(i).text().data(), response.instructions(i).text().size());
		}

		return apiResponse;
	}

	return nullptr;
}

__declspec(dllexport) void TED_DestroyDisassembleAddress(TED_DisassembleAddressResponse* response)
{
	if (response == nullptr) {
		return;
	}

	for (size_t i{ 0 }; i < response->instructionsCount; i++) {
		delete[] response->instructions[i];
		response->instructions[i] = nullptr;
	}

	delete response;
	response = nullptr;
}

__declspec(dllexport) TED_GenericResponse* TED_LoadModule(TED_Client* client, const char* path)
{
	if (client == nullptr || path == nullptr) {
		return nullptr;
	}

	auto* stub{ reinterpret_cast<TED::Grpc::TEDService::Stub*>(client) };

	grpc::ClientContext context{};
	TED::Grpc::LoadModuleRequest request{};
	request.set_path(path);

	TED::Grpc::GenericResponse response{};
	auto result{ stub->LoadModule(&context, request, &response) };
	if (!result.ok()) {
		return nullptr;
	}

	return BuildGenericResponse(response);
}

__declspec(dllexport) TED_GenericResponse* TED_UnloadModule(TED_Client* client, const char* path)
{
	if (client == nullptr || path == nullptr) {
		return nullptr;
	}

	auto* stub{ reinterpret_cast<TED::Grpc::TEDService::Stub*>(client) };

	grpc::ClientContext context{};
	TED::Grpc::UnloadModuleRequest request{};
	request.set_path(path);

	TED::Grpc::GenericResponse response{};
	auto result{ stub->UnloadModule(&context, request, &response) };
	if (!result.ok()) {
		return nullptr;
	}

	return BuildGenericResponse(response);
}

__declspec(dllexport) TED_ReadMemoryResponse* TED_ReadMemory(TED_Client* client, uint64_t address, uint32_t size)
{
	if (client == nullptr) {
		return nullptr;
	}

	auto* stub{ reinterpret_cast<TED::Grpc::TEDService::Stub*>(client) };

	grpc::ClientContext context{};
	TED::Grpc::ReadMemoryRequest request{};
	request.set_address(address);
	request.set_size(size);

	TED::Grpc::ReadMemoryResponse response{};
	auto result{ stub->ReadMemory(&context, request, &response) };
	if (!result.ok()) {
		return nullptr;
	}

	if (response.bytes().size() > 0) {
		auto* apiResponse{ new TED_ReadMemoryResponse{} };
		apiResponse->bytesCount = response.bytes().size();
		apiResponse->bytes = new unsigned char[response.bytes().size()]{};
		memcpy(apiResponse->bytes, response.bytes().data(), response.bytes().size());

		return apiResponse;
	}

	return nullptr;
}

__declspec(dllexport) void TED_DestroyReadMemory(TED_ReadMemoryResponse* response)
{
	if (response == nullptr) {
		return;
	}

	delete[] response->bytes;
	response->bytes = nullptr;

	delete response;
	response = nullptr;
}

__declspec(dllexport) TED_GenericResponse* TED_WriteMemory(TED_Client* client, uint64_t address, const unsigned char* bytes, uint32_t size)
{
	if (client == nullptr || bytes == nullptr || size == 0) {
		return nullptr;
	}

	auto* stub{ reinterpret_cast<TED::Grpc::TEDService::Stub*>(client) };

	grpc::ClientContext context{};
	TED::Grpc::WriteMemoryRequest request{};
	request.set_address(address);
	request.set_bytes(bytes, size);

	TED::Grpc::GenericResponse response{};
	stub->WriteMemory(&context, request, &response);

	return BuildGenericResponse(response);
}

__declspec(dllexport) TED_GenericResponse* TED_CreateConsole(TED_Client* client)
{
	if (client == nullptr) {
		return nullptr;
	}

	auto* stub{ reinterpret_cast<TED::Grpc::TEDService::Stub*>(client) };

	grpc::ClientContext context{};
	TED::Grpc::GenericResponse response{};
	auto result{ stub->CreateConsole(&context, TED::Grpc::Empty{}, &response) };
	if (!result.ok()) {
		return nullptr;
	}

	return BuildGenericResponse(response);
}

__declspec(dllexport) TED_GenericResponse* TED_DestroyConsole(TED_Client* client)
{
	if (client == nullptr) {
		return nullptr;
	}

	auto* stub{ reinterpret_cast<TED::Grpc::TEDService::Stub*>(client) };

	grpc::ClientContext context{};
	TED::Grpc::GenericResponse response{};
	auto result{ stub->DestroyConsole(&context, TED::Grpc::Empty{}, &response) };
	if (!result.ok()) {
		return nullptr;
	}

	return BuildGenericResponse(response);
}

__declspec(dllexport) TED_GenericResponse* TED_EnableInternalLogging(TED_Client* client)
{
	if (client == nullptr) {
		return nullptr;
	}

	auto* stub{ reinterpret_cast<TED::Grpc::TEDService::Stub*>(client) };

	grpc::ClientContext context{};
	TED::Grpc::GenericResponse response{};
	auto result{ stub->EnableInternalLogging(&context, TED::Grpc::Empty{}, &response) };
	if (!result.ok()) {
		return nullptr;
	}

	return BuildGenericResponse(response);
}

__declspec(dllexport) TED_GenericResponse* TED_DisableInternalLogging(TED_Client* client)
{
	if (client == nullptr) {
		return nullptr;
	}

	auto* stub{ reinterpret_cast<TED::Grpc::TEDService::Stub*>(client) };

	grpc::ClientContext context{};
	TED::Grpc::GenericResponse response{};
	auto result{ stub->DisableInternalLogging(&context, TED::Grpc::Empty{}, &response) };
	if (!result.ok()) {
		return nullptr;
	}

	return BuildGenericResponse(response);
}

__declspec(dllexport) TED_GenericResponse* TED_SetOptions(TED_Client* client, TED_Options* options)
{
	if (client == nullptr || options == nullptr) {
		return nullptr;
	}

	auto* stub{ reinterpret_cast<TED::Grpc::TEDService::Stub*>(client) };

	grpc::ClientContext context{};
	TED::Grpc::OptionsRequest request{};
	request.set_return_call_stack(options->returnCallStack);
	request.set_return_context(options->returnContext);
	request.set_return_symbol_info(options->returnSymbolInfo);
	request.set_use_invasive_breakpoints(options->useInvasiveBreakpoints);
	request.set_unsafe_memory_mode(options->unsafeMemoryMode);
	request.set_auto_disable_breakpoints_mode(options->autoDisableBreakpointsMode);
	request.set_symbol_path(options->symbolPath, strlen(options->symbolPath));
	request.set_kill_process_on_disconnect(options->killProcessOnDisconnect);

	TED::Grpc::GenericResponse response{};
	auto result{ stub->Options(&context, request, &response) };
	if (!result.ok()) {
		return nullptr;
	}

	return BuildGenericResponse(response);
}

__declspec(dllexport) TED_GenericResponse* TED_TestFunction(TED_Client* client)
{
	if (client == nullptr) {
		return nullptr;
	}

	auto* stub{ reinterpret_cast<TED::Grpc::TEDService::Stub*>(client) };

	grpc::ClientContext context{};
	TED::Grpc::GenericResponse response{};
	auto result{ stub->TestFunction(&context, TED::Grpc::Empty{}, &response) };
	if (!result.ok()) {
		return nullptr;
	}

	return BuildGenericResponse(response);
}

__declspec(dllexport) void TED_DestroyGeneric(TED_GenericResponse* response)
{
	if (response == nullptr) {
		return;
	}

	if (response->errorCodesCount > 0) {
		delete[] response->errorCodes;
		response->errorCodes = nullptr;
	}

	if (response->errorMessagesCount > 0) {
		for (size_t i{ 0 }; i < response->errorMessagesCount; i++) {
			delete response->errorMessages[i];
			response->errorMessages[i] = nullptr;
		}

		delete[] response->errorMessages;
		response->errorMessages = nullptr;
	}
}

