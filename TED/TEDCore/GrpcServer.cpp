#include "GrpcServer.h"

#include <algorithm>
#include <chrono>
#include <format>
#include <thread>
#include <unordered_set>
#include <vector>

#include "Breakpoint.h"
#include "CommonTypes.h"
#include "Console.h"
#include "Disassembler.h"
#include "Memory.h"
#include "Process.h"
#include "Symbols.h"

#include <concurrentqueue/concurrentqueue.h>

namespace TED
{
namespace Communication
{

TEDServiceImpl::TEDServiceImpl(unsigned long listenThreadId)
	: m_returnCallStack{},
	m_returnContext{},
	m_returnSymbolInfo{},
	m_useInvasiveBreakpoints{},
	m_unsafeMemoryMode{},
	m_autoDisableBreakpointsMode{},
	m_killProcessOnDisconnect{},
	m_listenThreadId{ listenThreadId },
	m_breakpointThreadId{}
{
	std::thread([this]() {
		m_breakpointThreadId = TED::Process::CurrentThreadId();
		m_running = true;
		StartSendBreakpointEventLoop();
		}).detach();
}

TEDServiceImpl::~TEDServiceImpl()
{
	m_running = false;
}

void TEDServiceImpl::StartSendBreakpointEventLoop()
{
	TED::Console::LogInternal("Beginning send breakpoint event loop.");

	while (m_running) {
		TED::Breakpoint::BreakpointEvent breakpointEvent{};
		while (m_subscribers.size() > 0 && TED::Breakpoint::breakpointEvents.try_dequeue(breakpointEvent)) {
			TED::Console::LogInternal(std::format("Dequeued breakpoint event. Queue size: {}",
				TED::Breakpoint::breakpointEvents.size_approx()));

			TED::Grpc::BreakpointResponse response{};

			response.set_process_id(breakpointEvent.processId);
			response.set_thread_id(breakpointEvent.threadId);
			response.set_source_address(breakpointEvent.source_address);
			response.set_destination_address(breakpointEvent.destination_address);

			auto builtContext{ BuildContext(breakpointEvent.context) };
			response.mutable_context()->CopyFrom(builtContext);

			auto builtCallStack{ BuildCallStack(breakpointEvent.stackFrames) };
			for (const auto& frame : builtCallStack) {
				response.mutable_call_stack()->add_stack_frame()->CopyFrom(frame);
			}

			auto subscriberIter{ m_subscribers.begin() };
			while (subscriberIter != m_subscribers.end()) {
				TED::Console::LogInternal("Sending breakpoint event to client.");
				const auto& writer{ subscriberIter->first };
				auto alive{ writer->Write(response) };
				if (!alive) {
					TED::Console::LogInternal("Client has disconnected. Erasing from subscribers.");
					subscriberIter->second->notify_one();
					subscriberIter = m_subscribers.erase(subscriberIter);
				}
				else {
					subscriberIter++;
				}
			}

			if (m_subscribers.size() == 0 && m_killProcessOnDisconnect) {
				TED::Console::LogInternal("All clients disconnected, terminating process.");
				TED::Process::Terminate();
			}
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}
}

grpc::Status TEDServiceImpl::GetBreakpoints(grpc::ServerContext* context,
	const TED::Grpc::Empty* request,
	grpc::ServerWriter<TED::Grpc::BreakpointResponse>* writer)
{
	std::mutex waitMutex{};
	std::unique_lock<std::mutex> waitLock{ waitMutex };
	std::condition_variable waitCondition{};

	TED::Console::LogInternal("Client has connected. Adding to subscribers.");

	m_subscribers.push_back({ writer, &waitCondition });
	waitCondition.wait(waitLock);

	TED::Console::LogInternal("Client has disconnected. Client subscribe thread exiting.");

	return grpc::Status::OK;
}

grpc::Status TEDServiceImpl::GetModules(grpc::ServerContext* context,
	const TED::Grpc::Empty* request,
	TED::Grpc::GetModulesResponse* response)
{
	TED::Console::LogInternal("Get modules request received.");

	auto modules{ TED::Process::GetModules() };
	TED::Console::LogInternal(std::format("Found {} modules", modules.size()));

	for (const auto& module : modules) {
		auto new_module_info = response->add_module_info();
		new_module_info->set_name(module.name);
		new_module_info->set_base_address(module.baseAddress);
		new_module_info->set_size(module.size);
		if (!module.executableSectionNames.empty()) {
			for (size_t i{ 0 }; i < module.executableSectionNames.size(); i++) {
				auto new_executable_section_info = new_module_info->add_executable_sections();
				new_executable_section_info->set_name(module.executableSectionNames[i]);
				new_executable_section_info->set_address(module.executableSectionBaseAddresses[i]);
				new_executable_section_info->set_size(module.executableSectionSizes[i]);
			}
		}
	}

	return grpc::Status::OK;
}

grpc::Status TEDServiceImpl::EnableBreakAllCallsInModule(grpc::ServerContext* context,
	const TED::Grpc::EnableBreakAllCallsInModuleRequest* request,
	TED::Grpc::GenericResponse* response)
{
	TED::Console::LogInternal("Enable break all calls in module request received.");

	return ModifyModuleBreakpoints(context,
		request->module_name(),
		GetSetBreakpointFunction(),
		false,
		response);
}

grpc::Status TEDServiceImpl::DisableBreakAllCallsInModule(grpc::ServerContext* context,
	const TED::Grpc::DisableBreakAllCallsInModuleRequest* request,
	TED::Grpc::GenericResponse* response)
{
	TED::Console::LogInternal("Disable break all calls in module request received.");

	auto modules{ TED::Process::GetModules() };
	auto moduleIter{ FindModule(modules, request->module_name()) };

	auto result{ moduleIter != modules.end() };
	if (result) {
		TED::Console::LogInternal("Module is found, removing all breakpoints.");

		auto threadIds{ GetApplicationThreadIds() };

		TED::Process::SuspendThreads(threadIds);

		result &= TED::Breakpoint::UnsetAllBreakpointsInModule(request->module_name());

		TED::Process::ResumeThreads(threadIds);

	}
	else {
		auto errorMessage = std::format("Module {} was not found", request->module_name());

		TED::Console::LogInternal(errorMessage);
		response->add_error_message(errorMessage);
	}

	return GenericResult(result, response);
}

grpc::Status TEDServiceImpl::EnableBreakCallByAddress(grpc::ServerContext* context,
	const TED::Grpc::EnableBreakCallByAddressRequest* request,
	TED::Grpc::GenericResponse* response)
{
	TED::Console::LogInternal("Enable break call by address request received.");

	auto result{ GetSetBreakpointFunction()(request->address(), m_returnCallStack, false) };
	return GenericResult(result, response);
}

grpc::Status TEDServiceImpl::DisableBreakCallByAddress(grpc::ServerContext* context,
	const TED::Grpc::DisableBreakCallByAddressRequest* request,
	TED::Grpc::GenericResponse* response)
{
	TED::Console::LogInternal("Disable break call by address request received.");

	auto result{ TED::Breakpoint::UnsetBreakpoint(request->address(), m_returnCallStack, false) };
	return GenericResult(result, response);
}

grpc::Status TEDServiceImpl::EnableBreakCallByName(grpc::ServerContext* context,
	const TED::Grpc::EnableBreakCallByNameRequest* request,
	TED::Grpc::GenericResponse* response)
{
	TED::Console::LogInternal("Enable break call by name request received.");

	auto address{ TED::Symbols::SymbolAddressFromName(request->name()) };
	if (address) {
		TED::Console::LogInternal(std::format("Address found for {}", request->name()));

		auto result{ GetSetBreakpointFunction()(address, m_returnCallStack, false) };
		return GenericResult(result, response);
	}
	else {
		auto errorMessage = std::format("Address not found for symbol {}", request->name());

		TED::Console::LogInternal(errorMessage);
		response->add_error_message(errorMessage);
	}

	return GenericResult(false, response);
}

grpc::Status TEDServiceImpl::DisableBreakCallByName(grpc::ServerContext* context,
	const TED::Grpc::DisableBreakCallByNameRequest* request,
	TED::Grpc::GenericResponse* response)
{
	TED::Console::LogInternal("Disable break call by name request received.");

	auto address{ TED::Symbols::SymbolAddressFromName(request->name()) };
	if (address) {
		TED::Console::LogInternal(std::format("Address found for {}", request->name()));

		auto result{ TED::Breakpoint::UnsetBreakpoint(address, m_returnCallStack, false) };
		return GenericResult(result, response);
	}
	else {
		auto errorMessage = std::format("Address not found for symbol {}", request->name());

		TED::Console::LogInternal(errorMessage);
		response->add_error_message(errorMessage);
	}

	return GenericResult(false, response);
}

grpc::Status TEDServiceImpl::EnableBreakpointByAddress(grpc::ServerContext* context,
	const TED::Grpc::EnableBreakpointByAddressRequest* request,
	TED::Grpc::GenericResponse* response)
{
	TED::Console::LogInternal("Enable single breakpoint by address request received.");

	auto result{ GetSetBreakpointFunction()(request->address(), m_returnCallStack, true) };
	return GenericResult(result, response);
}

grpc::Status TEDServiceImpl::DisableBreakpointByAddress(grpc::ServerContext* context,
	const TED::Grpc::DisableBreakpointByAddressRequest* request,
	TED::Grpc::GenericResponse* response)
{
	TED::Console::LogInternal("Disable single breakpoint by address request received.");

	auto result{ TED::Breakpoint::UnsetBreakpoint(request->address(), m_returnCallStack, true) };
	return GenericResult(result, response);
}

grpc::Status TEDServiceImpl::EnableBreakpointByName(grpc::ServerContext* context,
	const TED::Grpc::EnableBreakpointByNameRequest* request,
	TED::Grpc::GenericResponse* response)
{
	TED::Console::LogInternal("Enable single breakpoint by name request received.");

	auto address{ TED::Symbols::SymbolAddressFromName(request->name()) };
	if (address) {
		TED::Console::LogInternal(std::format("Address found for {}", request->name()));

		auto result{ GetSetBreakpointFunction()(address, m_returnCallStack, true) };
		return GenericResult(result, response);
	}
	else {
		auto errorMessage = std::format("Address not found for symbol {}", request->name());

		TED::Console::LogInternal(errorMessage);
		response->add_error_message(errorMessage);
	}

	return GenericResult(false, response);
}

grpc::Status TEDServiceImpl::DisableBreakpointByName(grpc::ServerContext* context,
	const TED::Grpc::DisableBreakpointByNameRequest* request,
	TED::Grpc::GenericResponse* response)
{
	TED::Console::LogInternal("Disable single breakpoint by name request received.");

	auto address{ TED::Symbols::SymbolAddressFromName(request->name()) };
	if (address) {
		auto result{ TED::Breakpoint::UnsetBreakpoint(address, m_returnCallStack, true) };
		return GenericResult(result, response);
	}
	else {
		auto errorMessage = std::format("Address not found for symbol {}", request->name());

		TED::Console::LogInternal(errorMessage);
		response->add_error_message(errorMessage);
	}

	return GenericResult(false, response);
}

grpc::Status TEDServiceImpl::DisassembleAddress(grpc::ServerContext* context,
	const TED::Grpc::DisassembleAddressRequest* request,
	TED::Grpc::DisassembleAddressResponse* response)
{
	TED::Console::LogInternal("Disassemble address request received.");

	auto disassembler{ TED::Disassembler::Disassembler() };
	auto result{ disassembler.GetInstructions(request->address(), request->size()) };

	for (const auto& instruction : result) {
		TED::Grpc::Instruction builtInstruction{};
		builtInstruction.set_address(instruction.address);
		builtInstruction.set_bytes(instruction.bytes.data(), instruction.bytes.size());
		builtInstruction.set_mnemonic(instruction.mnemonic);
		builtInstruction.set_text(instruction.opcodes);
		response->add_instructions()->CopyFrom(builtInstruction);
	}

	return grpc::Status::OK;
}

grpc::Status TEDServiceImpl::LoadModule(grpc::ServerContext* context,
	const TED::Grpc::LoadModuleRequest* request,
	TED::Grpc::GenericResponse* response)
{
	TED::Console::LogInternal("Load modules request received.");

	auto result{ TED::Process::LoadModule(request->path()) };
	return GenericResult(result, response);
}

grpc::Status TEDServiceImpl::UnloadModule(grpc::ServerContext* context,
	const TED::Grpc::UnloadModuleRequest* request,
	TED::Grpc::GenericResponse* response)
{
	TED::Console::LogInternal("Unload modules request received.");

	auto result{ TED::Process::UnloadModule(request->path()) };
	return GenericResult(result, response);
}

grpc::Status TEDServiceImpl::ReadMemory(grpc::ServerContext* context,
	const TED::Grpc::ReadMemoryRequest* request,
	TED::Grpc::ReadMemoryResponse* response)
{
	TED::Console::LogInternal("Read memory request received.");

	auto result{ TED::Memory::ReadMemory(request->address(), request->size()) };
	response->set_bytes(result.data(), result.size());

	return grpc::Status::OK;
}

grpc::Status TEDServiceImpl::WriteMemory(grpc::ServerContext* context,
	const TED::Grpc::WriteMemoryRequest* request,
	TED::Grpc::GenericResponse* response)
{
	TED::Console::LogInternal("Write memory request received.");

	std::vector<unsigned char> bytes{ request->bytes().begin(), request->bytes().end() };
	auto result{ TED::Memory::WriteMemory(request->address(), bytes) };
	return GenericResult(result, response);
}

grpc::Status TEDServiceImpl::CreateConsole(grpc::ServerContext* context,
	const TED::Grpc::Empty* request,
	TED::Grpc::GenericResponse* response)
{
	TED::Console::LogInternal("Create console request received.");

	auto result{ TED::Console::CreateConsole() };
	return GenericResult(result, response);
}

grpc::Status TEDServiceImpl::DestroyConsole(grpc::ServerContext* context,
	const TED::Grpc::Empty* request,
	TED::Grpc::GenericResponse* response)
{
	TED::Console::LogInternal("Destroy console request received.");

	auto result{ TED::Console::DestroyConsole() };
	return GenericResult(result, response);
}

grpc::Status TEDServiceImpl::EnableInternalLogging(grpc::ServerContext* context,
	const TED::Grpc::Empty* request,
	TED::Grpc::GenericResponse* response)
{
	TED::Console::LogInternal("Enable internal logging request received.");

	TED::Console::EnableLogging();
	return GenericResult(true, response);
}

grpc::Status TEDServiceImpl::DisableInternalLogging(grpc::ServerContext* context,
	const TED::Grpc::Empty* request,
	TED::Grpc::GenericResponse* response)
{
	TED::Console::LogInternal("Disable internal logging request received.");

	TED::Console::DisableLogging();
	return GenericResult(true, response);
}

grpc::Status TEDServiceImpl::Options(grpc::ServerContext* context,
	const TED::Grpc::OptionsRequest* request,
	TED::Grpc::GenericResponse* response)
{
	TED::Console::LogInternal("Options request received.");

	this->m_returnCallStack = request->return_call_stack();
	this->m_returnContext = request->return_context();
	this->m_returnSymbolInfo = request->return_symbol_info();
	this->m_unsafeMemoryMode = request->unsafe_memory_mode();
	this->m_useInvasiveBreakpoints = request->use_invasive_breakpoints();
	this->m_autoDisableBreakpointsMode = request->auto_disable_breakpoints_mode();
	this->m_killProcessOnDisconnect = request->kill_process_on_disconnect();
	if (m_returnSymbolInfo) {
		TED::Symbols::DisableSymbols();
		TED::Symbols::EnableSymbols(request->symbol_path());
	}
	else {
		TED::Symbols::DisableSymbols();
	}
	if (m_unsafeMemoryMode) {
		TED::Memory::EnableUnsafeMemoryMode();
	}
	else {
		TED::Memory::DisableUnsafeMemoryMode();
	}
	if (m_autoDisableBreakpointsMode) {
		TED::Breakpoint::EnableAutoDisableBreakpointMode();
	}
	else {
		TED::Breakpoint::DisableAutoDisableBreakpointMode();
	}

	return GenericResult(true, response);
}

grpc::Status TEDServiceImpl::TestFunction(grpc::ServerContext* context,
	const TED::Grpc::Empty* request,
	TED::Grpc::GenericResponse* response)
{
	TED::Console::LogInternal("Test function request received.");

	using testFunctionPtr = std::add_pointer<decltype(IsCharAlphaA)>::type;
	auto testFunction{ reinterpret_cast<testFunctionPtr>(
		GetProcAddress(GetModuleHandleA("user32.dll"), "IsCharAlphaA")) };

	auto result{ TED::Breakpoint::SetMemoryBreakpoint(reinterpret_cast<TED::Address>(testFunction), true, false) };
	testFunction('A');
	std::cout << "stdout: A message 1" << std::endl;
	std::cerr << "stderr: A message 1" << std::endl;
	result &= TED::Breakpoint::UnsetMemoryBreakpoint(reinterpret_cast<TED::Address>(testFunction), true, false);

	result &= TED::Breakpoint::SetInt3Breakpoint(reinterpret_cast<TED::Address>(testFunction), true, false);;
	testFunction('A');
	std::cout << "stdout: A message 2" << std::endl;
	std::cerr << "stderr: A message 2" << std::endl;
	result &= TED::Breakpoint::UnsetInt3Breakpoint(reinterpret_cast<TED::Address>(testFunction), true, false);

	return GenericResult(result, response);
}

grpc::Status TEDServiceImpl::GenericResult(bool result, TED::Grpc::GenericResponse* response) const
{
	response->set_success(result);
	if (!result) {
		response->add_last_error_code(GetLastError());
	}

	return grpc::Status::OK;
}

grpc::Status TEDServiceImpl::ModifyModuleBreakpoints(grpc::ServerContext* context,
	const std::string& moduleName,
	const std::function<bool(TED::Address, bool, bool)> operation,
	bool isImmediateBreakpoint,
	TED::Grpc::GenericResponse* response) const
{
	response->set_success(true);

	auto modules{ TED::Process::GetModules() };
	auto moduleIter{ FindModule(modules, moduleName) };

	if (moduleIter != modules.end()) {
		auto disassembler{ TED::Disassembler::Disassembler() };
		auto callInstructions{ GetCallInstructions(moduleIter) };

		TED::Console::LogInternal(std::format("Found {} call instructions for module {}.",
			callInstructions.size(), moduleName));

		if (!callInstructions.empty()) {

			auto threadIds{ GetApplicationThreadIds() };

			TED::Process::SuspendThreads(threadIds);

			for (const auto& callInstruction : callInstructions) {
				auto result{ operation(callInstruction, m_returnCallStack, isImmediateBreakpoint) };
				if (!result) {
					response->set_success(false);
					auto errorMessage = std::format("Could not change breakpoint state on {}.", callInstruction);

					TED::Console::LogInternal(errorMessage);
					response->add_error_message(errorMessage);
				}
			}

			TED::Process::ResumeThreads(threadIds);

			TED::Console::LogInternal("Breakpoints modified successfully.");
		}
		else {
			response->set_success(false);
			auto errorMessage = std::format("Could not get instructions for address {:X}.", moduleIter->baseAddress);

			TED::Console::LogInternal(errorMessage);
			response->add_error_message(errorMessage);
		}
	}
	else {
		response->set_success(false);
		auto errorMessage = std::format("Could not find module {}.", moduleName);

		TED::Console::LogInternal(errorMessage);
		response->add_error_message(errorMessage);
	}

	return grpc::Status::OK;
}

std::vector<TED::Process::Module>::iterator TEDServiceImpl::FindModule(std::vector<TED::Process::Module>& modules, std::string moduleName) const
{
	auto moduleNameLower{ moduleName };
	std::transform(moduleNameLower.begin(), moduleNameLower.end(), moduleNameLower.begin(),
		[](unsigned char c) { return std::tolower(c); });
	auto moduleIter{ std::find_if(modules.begin(), modules.end(),
		[&](const auto& elem) {
			auto currentModuleLower{elem.name};
			std::transform(currentModuleLower.begin(), currentModuleLower.end(), currentModuleLower.begin(),
					[](unsigned char c) { return std::tolower(c); });
			return currentModuleLower == moduleNameLower; }
	) };

	return moduleIter;
}

std::vector<TED::Address> TEDServiceImpl::GetCallInstructions(std::vector<TED::Process::Module>::iterator moduleIter) const
{
	auto disassembler{ TED::Disassembler::Disassembler() };
	std::vector<TED::Address> callInstructions{};

	for (size_t i{ 0 }; i < moduleIter->executableSectionNames.size(); i++) {
		auto sectionInstructions{ disassembler.GetCallInstructions(
			moduleIter->executableSectionBaseAddresses[i], moduleIter->executableSectionSizes[i]) };
		callInstructions.insert(callInstructions.end(), sectionInstructions.begin(), sectionInstructions.end());
	}

	return callInstructions;
}

std::vector<unsigned long> TEDServiceImpl::GetApplicationThreadIds() const
{
	auto threadIds{ TED::Process::GetThreadIds() };
	std::unordered_set<unsigned long> dontSuspendThreads{ {m_listenThreadId, m_breakpointThreadId, TED::Process::CurrentThreadId()} };
	auto newEnd{ std::remove_if(threadIds.begin(), threadIds.end(), [&](const unsigned long threadId) {
		return dontSuspendThreads.contains(threadId);
	}) };

	threadIds.erase(newEnd, threadIds.end());

	return threadIds;
}

TED::Grpc::Context TEDServiceImpl::BuildContext(const CONTEXT& context) const
{
	TED::Grpc::Context builtContext{};
	if (!m_returnContext) {
		return builtContext;
	}
#ifdef _M_IX86
	builtContext.mutable_general_registers()->set_rax(context.Eax);
	builtContext.mutable_general_registers()->set_rcx(context.Ecx);
	builtContext.mutable_general_registers()->set_rdx(context.Ebx);
	builtContext.mutable_general_registers()->set_rbx(context.Edx);
	builtContext.mutable_general_registers()->set_rsp(context.Esp);
	builtContext.mutable_general_registers()->set_rbp(context.Ebp);
	builtContext.mutable_general_registers()->set_rsi(context.Esi);
	builtContext.mutable_general_registers()->set_rdi(context.Edi);
	builtContext.mutable_general_registers()->set_rip(context.Eip);
#elif defined _M_AMD64
	builtContext.mutable_general_registers()->set_rax(context.Rax);
	builtContext.mutable_general_registers()->set_rcx(context.Rcx);
	builtContext.mutable_general_registers()->set_rdx(context.Rdx);
	builtContext.mutable_general_registers()->set_rbx(context.Rbx);
	builtContext.mutable_general_registers()->set_rsp(context.Rsp);
	builtContext.mutable_general_registers()->set_rbp(context.Rbp);
	builtContext.mutable_general_registers()->set_rsi(context.Rsi);
	builtContext.mutable_general_registers()->set_rdi(context.Rdi);
	builtContext.mutable_general_registers()->set_rip(context.Rip);

	builtContext.mutable_general_registers_x64()->set_r8(context.R8);
	builtContext.mutable_general_registers_x64()->set_r9(context.R9);
	builtContext.mutable_general_registers_x64()->set_r10(context.R10);
	builtContext.mutable_general_registers_x64()->set_r11(context.R11);
	builtContext.mutable_general_registers_x64()->set_r12(context.R12);
	builtContext.mutable_general_registers_x64()->set_r13(context.R13);
	builtContext.mutable_general_registers_x64()->set_r14(context.R14);
	builtContext.mutable_general_registers_x64()->set_r15(context.R15);
#else
#error "Unsupported architecture"
#endif

	builtContext.mutable_debug_registers()->set_dr0(context.Dr0);
	builtContext.mutable_debug_registers()->set_dr1(context.Dr1);
	builtContext.mutable_debug_registers()->set_dr2(context.Dr2);
	builtContext.mutable_debug_registers()->set_dr3(context.Dr3);
	builtContext.mutable_debug_registers()->set_dr6(context.Dr6);
	builtContext.mutable_debug_registers()->set_dr7(context.Dr7);

	builtContext.mutable_segment_registers()->set_cs(context.SegCs);
	builtContext.mutable_segment_registers()->set_ds(context.SegDs);
	builtContext.mutable_segment_registers()->set_es(context.SegEs);
	builtContext.mutable_segment_registers()->set_fs(context.SegFs);
	builtContext.mutable_segment_registers()->set_gs(context.SegGs);
	builtContext.mutable_segment_registers()->set_ss(context.SegSs);

	builtContext.set_processor_flags(context.EFlags);

	return builtContext;
}

std::vector<TED::Grpc::StackFrame> TEDServiceImpl::BuildCallStack(const std::vector<STACKFRAME64>& stackFrames) const
{
	std::vector<TED::Grpc::StackFrame> builtCallStack{};
	if (!m_returnCallStack) {
		return builtCallStack;
	}

	for (const auto& stackFrame : stackFrames) {
		TED::Grpc::StackFrame builtFrame{};

		builtFrame.set_rip(stackFrame.AddrPC.Offset);
		builtFrame.set_return_address(stackFrame.AddrReturn.Offset);
		builtFrame.set_stack_pointer(stackFrame.AddrStack.Offset);
		for (const auto& parameter : stackFrame.Params) {
			builtFrame.add_parameters(parameter);
		}

		if (m_returnSymbolInfo) {
			auto functionName{ TED::Symbols::SymbolNameFromAddress(stackFrame.AddrPC.Offset) };
			builtFrame.mutable_symbols()->set_function_name(functionName);
		}

		builtCallStack.push_back(builtFrame);
	}

	return builtCallStack;
}

const std::function<bool(TED::Address, bool, bool)> TEDServiceImpl::GetSetBreakpointFunction() const
{
	return m_useInvasiveBreakpoints ? TED::Breakpoint::SetInt3Breakpoint : TED::Breakpoint::SetMemoryBreakpoint;
}


}
}
