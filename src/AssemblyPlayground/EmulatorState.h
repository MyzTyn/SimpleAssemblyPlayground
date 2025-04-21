//
//  EmulatorState.h
//  SimpleAssemblyPlayground
//
//  Created by MyzTyn on 2025/04/07.
//

#ifndef EmulatorState_h
#define EmulatorState_h

#include <array>
#include <functional>
#include <vector>

#include "AppUI.h"
#include "MiniKernel.h"
#include "capstone/capstone.h"
#include "keystone/keystone.h"
#include "unicorn/unicorn.h"

#define MEMORY_SIZE 0x2000
#define REGISTERS_TOTAL 9

struct ExecutableData {
  // ## Configuration ##
  uint32_t default_eax_value;
  uint32_t default_ebx_value;
  uint32_t default_ecx_value;
  uint32_t default_edx_value;
  uint32_t default_esp_value;
  uint32_t default_ebp_value;
  uint32_t default_esi_value;
  uint32_t default_edi_value;
  // ToDo: Use EIP instead of start
  // uint32_t default_eip_value;
  uint32_t default_start_address; // AKA EIP
  uint64_t default_end_address;

  // Assembly Code
  std::string code;

  // ## Bin ##
  uint8_t *bin;
  size_t bin_size;

  // ## Disassemble ##
  cs_insn *instructions;
  size_t instruction_size;

  // ## Cleanup ##
  ~ExecutableData() {
    free(bin);
    free(instructions);
  }
};

// ToDo: Rename to EmulatorState
struct CpuState {
  uc_engine *uc;

  // CPU Registers
  std::array<uint32_t, REGISTERS_TOTAL> registers;
  std::array<void *, REGISTERS_TOTAL> register_ptrs;

  // Memory
  std::array<uint8_t, MEMORY_SIZE> memory;

  // Methods
  void update_registers();
  void read_stack();
};

class EmulatorState {
 public:
  // ## Core ##
  // CPU Emulator
  uc_engine *uc;
  MiniKernel kernel;

  // Registers
  std::array<uint32_t, REGISTERS_TOTAL> registers;
  std::array<void *, REGISTERS_TOTAL> register_ptrs;

  // Memory
  std::array<uint8_t, MEMORY_SIZE> memory;
  // Stack pair<ADDRESS, VALUE>
  std::vector<std::pair<uint64_t, uint32_t>> stack;

  // ## TEMPO ##
  const ExecutableData* executable_data;
  std::function<void(uint32_t)> update_pc_fn;
  std::function<bool(uint64_t)> has_breakpoint;

  EmulatorState();
  ~EmulatorState();

  // Run the emulator
  void run();
  // Step by Step
  void step();
  // Clear the state
  void reset();

  // ## Update the Registers & Stack ##
  void update_registers();
  void read_stack();
};

#endif /* EmulatorState_h */
