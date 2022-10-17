#pragma comment(lib, "Ws2_32.lib")

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "iphlpapi.lib")

#define WIN32_LEAN_AND_MEAN

#include <thread>

#include "Breakpoint.h"
#include "Console.h"
#include "GrpcServer.h"

#include <Windows.h>

#include <grpc/grpc.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>

#include "Proto/TED.grpc.pb.h"

static PVOID exceptionHandler{};
static std::unique_ptr<grpc::Server> server{};

void StartGrpcServer() {
	std::thread([]() {
		std::string server_address("0.0.0.0:50051");
		TED::Communication::TEDServiceImpl service(GetCurrentThreadId());

		grpc::ServerBuilder builder;
		builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
		builder.RegisterService(&service);
		server = std::move(builder.BuildAndStart());

		server->Wait();
		}).detach();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID reserved)
{
	if (dwReason == DLL_PROCESS_ATTACH) {
		exceptionHandler = AddVectoredExceptionHandler(1, TED::Breakpoint::BreakpointHandler);

		StartGrpcServer();
	}

	return TRUE;
}
