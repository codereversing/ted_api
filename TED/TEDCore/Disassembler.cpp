#include "Disassembler.h"

#include <exception>
#include <format>

namespace TED
{
namespace Disassembler
{

#ifdef _M_IX86
static cs_mode Mode = CS_MODE_32;
#elif defined(_M_AMD64)
static cs_mode Mode = CS_MODE_64;
#else
#error "Unsupported architecture"
#endif

Disassembler::Disassembler()
	: m_handle{}
{
	auto result{ cs_open(CS_ARCH_X86, Mode, &m_handle) };
	if (result != CS_ERR_OK) {
		throw std::runtime_error(
			std::format("Could not initialize disassembly engine: {}", static_cast<int>(result)));
	}

	cs_option(m_handle, CS_OPT_DETAIL, CS_OPT_ON);
	cs_option(m_handle, CS_OPT_SKIPDATA, CS_OPT_ON);
}

Disassembler::~Disassembler()
{
	cs_close(&m_handle);
}

std::vector<Address> Disassembler::GetCallInstructions(Address startAddress, size_t size) const
{
	std::vector<Address> callInstructions{};

	auto call{ std::string{"call"} };

	cs_insn* instructions{};

	size_t disassembleSize{ 0x10000 };
	const auto endAddress{ startAddress + size };
	while (startAddress < endAddress) {
		size_t disassembledBytesSize{};

		auto count{ cs_disasm(m_handle, reinterpret_cast<uint8_t*>(startAddress), disassembleSize, 0, 0, &instructions) };
		if (count > 0) {
			for (size_t j{ 0 }; j < count; j++) {
				if (call == instructions[j].mnemonic) {
					callInstructions.push_back(startAddress + instructions[j].address);
				}
				disassembledBytesSize += instructions[j].size;
			}

			cs_free(instructions, count);
		}

		startAddress += disassembledBytesSize;
		disassembleSize = std::min(disassembleSize, static_cast<size_t>(endAddress - startAddress));
	}

	return callInstructions;
}

std::vector<InstructionInfo> Disassembler::GetInstructions(Address startAddress, size_t size) const
{
	std::vector<InstructionInfo> callInstructions{};

	cs_insn* instructions{};
	auto count{ cs_disasm(m_handle, reinterpret_cast<uint8_t*>(startAddress), size, 0, 0, &instructions) };
	if (count > 0) {
		for (size_t i{ 0 }; i < count; i++) {
			InstructionInfo instructionInfo{};
			instructionInfo.address = startAddress + instructions[i].address;
			instructionInfo.mnemonic.assign(instructions[i].mnemonic);
			instructionInfo.opcodes.assign(instructions[i].op_str);
			instructionInfo.bytes.assign(instructions[i].bytes, std::begin(instructions[i].bytes) + instructions[i].size);

			callInstructions.push_back(instructionInfo);
		}

		cs_free(instructions, count);
	}

	return callInstructions;
}

size_t Disassembler::GetFunctionSize(Address startAddress) const
{
	size_t functionSize{};

	auto ret{ std::string{"ret"} };
	size_t offset{};

	do {
		cs_insn* instructions{};
		auto count{ cs_disasm(m_handle, reinterpret_cast<uint8_t*>(startAddress + functionSize), 0x20, 0, 1, &instructions) };
		if (count > 0) {
			functionSize += instructions[0].size;
			if (ret == instructions[0].mnemonic) {
				break;
			}
			cs_free(instructions, count);
		}
	} while (functionSize < 0x1000);

	return functionSize;
}

}
}