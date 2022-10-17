#pragma once

#include <atomic>
#include <condition_variable>
#include <functional>
#include <vector>

#include <Windows.h>
#include <DbgHelp.h>

#include <grpc/grpc.h>
#include <grpcpp/server.h>

#include "Proto/TED.pb.h"
#include "Proto/TED.grpc.pb.h"

#include "Memory.h"
#include "Process.h"

namespace TED
{
namespace Communication
{

class TEDServiceImpl final : public TED::Grpc::TEDService::Service
{
public:
	TEDServiceImpl(unsigned long listenThreadId);
	~TEDServiceImpl();

	grpc::Status GetBreakpoints(grpc::ServerContext* context,
		const TED::Grpc::Empty* request,
		grpc::ServerWriter<TED::Grpc::BreakpointResponse>* writer) override;

	grpc::Status GetModules(grpc::ServerContext* context,
		const TED::Grpc::Empty* request,
		TED::Grpc::GetModulesResponse* response) override;

	grpc::Status EnableBreakAllCallsInModule(grpc::ServerContext* context,
		const TED::Grpc::EnableBreakAllCallsInModuleRequest* request,
		TED::Grpc::GenericResponse* response) override;
	grpc::Status DisableBreakAllCallsInModule(grpc::ServerContext* context,
		const TED::Grpc::DisableBreakAllCallsInModuleRequest* request,
		TED::Grpc::GenericResponse* response) override;
	grpc::Status EnableBreakCallByAddress(grpc::ServerContext* context,
		const TED::Grpc::EnableBreakCallByAddressRequest* request,
		TED::Grpc::GenericResponse* response) override;
	grpc::Status DisableBreakCallByAddress(grpc::ServerContext* context,
		const TED::Grpc::DisableBreakCallByAddressRequest* request,
		TED::Grpc::GenericResponse* response) override;
	grpc::Status EnableBreakCallByName(grpc::ServerContext* context,
		const TED::Grpc::EnableBreakCallByNameRequest* request,
		TED::Grpc::GenericResponse* response) override;
	grpc::Status DisableBreakCallByName(grpc::ServerContext* context,
		const TED::Grpc::DisableBreakCallByNameRequest* request,
		TED::Grpc::GenericResponse* response) override;

	grpc::Status EnableBreakpointByAddress(grpc::ServerContext* context,
		const TED::Grpc::EnableBreakpointByAddressRequest* request,
		TED::Grpc::GenericResponse* response) override;
	grpc::Status DisableBreakpointByAddress(grpc::ServerContext* context,
		const TED::Grpc::DisableBreakpointByAddressRequest* request,
		TED::Grpc::GenericResponse* response) override;
	grpc::Status EnableBreakpointByName(grpc::ServerContext* context,
		const TED::Grpc::EnableBreakpointByNameRequest* request,
		TED::Grpc::GenericResponse* response) override;
	grpc::Status DisableBreakpointByName(grpc::ServerContext* context,
		const TED::Grpc::DisableBreakpointByNameRequest* request,
		TED::Grpc::GenericResponse* response) override;

	grpc::Status DisassembleAddress(grpc::ServerContext* context,
		const TED::Grpc::DisassembleAddressRequest* request,
		TED::Grpc::DisassembleAddressResponse* response) override;

	grpc::Status LoadModule(grpc::ServerContext* context,
		const TED::Grpc::LoadModuleRequest* request,
		TED::Grpc::GenericResponse* response) override;
	grpc::Status UnloadModule(grpc::ServerContext* context,
		const TED::Grpc::UnloadModuleRequest* request,
		TED::Grpc::GenericResponse* response) override;

	grpc::Status ReadMemory(grpc::ServerContext* context,
		const TED::Grpc::ReadMemoryRequest* request,
		TED::Grpc::ReadMemoryResponse* response) override;
	grpc::Status WriteMemory(grpc::ServerContext* context,
		const TED::Grpc::WriteMemoryRequest* request,
		TED::Grpc::GenericResponse* response) override;

	grpc::Status CreateConsole(grpc::ServerContext* context,
		const TED::Grpc::Empty* request,
		TED::Grpc::GenericResponse* response) override;
	grpc::Status DestroyConsole(grpc::ServerContext* context,
		const TED::Grpc::Empty* request,
		TED::Grpc::GenericResponse* response) override;

	grpc::Status EnableInternalLogging(grpc::ServerContext* context,
		const TED::Grpc::Empty* request,
		TED::Grpc::GenericResponse* response) override;
	grpc::Status DisableInternalLogging(grpc::ServerContext* context,
		const TED::Grpc::Empty* request,
		TED::Grpc::GenericResponse* response) override;

	grpc::Status Options(grpc::ServerContext* context,
		const TED::Grpc::OptionsRequest* request,
		TED::Grpc::GenericResponse* response) override;

	grpc::Status TestFunction(grpc::ServerContext* context,
		const TED::Grpc::Empty* request,
		TED::Grpc::GenericResponse* response) override;

private:
	grpc::Status GenericResult(bool result, TED::Grpc::GenericResponse* response) const;

	grpc::Status ModifyModuleBreakpoints(grpc::ServerContext* context,
		const std::string& moduleName,
		const std::function<bool(unsigned long long, bool, bool operation)>,
		bool isImmediateBreakpoint,
		TED::Grpc::GenericResponse* response) const;

	const std::function<bool(TED::Address, bool, bool)> GetSetBreakpointFunction() const;

	std::vector<TED::Process::Module>::iterator FindModule(std::vector<TED::Process::Module>& modules, std::string moduleName) const;
	std::vector<TED::Address> GetCallInstructions(std::vector<TED::Process::Module>::iterator moduleIter) const;
	std::vector<unsigned long> GetApplicationThreadIds() const;

	TED::Grpc::Context BuildContext(const CONTEXT& context) const;
	std::vector<TED::Grpc::StackFrame> BuildCallStack(const std::vector<STACKFRAME64>& stackFrames) const;

	void StartSendBreakpointEventLoop();

	unsigned long m_listenThreadId;
	unsigned long m_breakpointThreadId;

	bool m_returnCallStack;
	bool m_returnContext;
	bool m_returnSymbolInfo;
	bool m_useInvasiveBreakpoints;
	bool m_unsafeMemoryMode;
	bool m_autoDisableBreakpointsMode;
	bool m_killProcessOnDisconnect;

	std::atomic_bool m_running;
	std::vector<std::pair<grpc::ServerWriter<TED::Grpc::BreakpointResponse>*, std::condition_variable*>> m_subscribers;
};

}
}
