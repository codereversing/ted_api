#pragma once

#include <string>
#include <vector>

#include "CommonTypes.h"

#include <capstone/capstone.h>

namespace TED
{
namespace Disassembler
{

typedef struct {
	Address address;
	std::string mnemonic;
	std::string opcodes;
	std::vector<unsigned char> bytes;
} InstructionInfo;

class Disassembler
{
public:
	Disassembler();
	virtual ~Disassembler();

	std::vector<Address> GetCallInstructions(Address startAddress, size_t size) const;
	std::vector<InstructionInfo> GetInstructions(Address startAddress, size_t size) const;

	size_t GetFunctionSize(Address startAddress) const;

private:
	csh m_handle;
};

}
}