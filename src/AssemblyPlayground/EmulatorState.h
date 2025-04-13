//
//  EmulatorState.h
//  ia32_emulator
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

// ToDo: Remove the TEMPO

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
  uint32_t default_eip_value;
  uint32_t default_start_address;
  uint64_t default_end_address;

  // Assembly Code
  std::string code;

  // ## Bin ##
  uint8_t *bin;
  size_t bin_size;

  // ## Disassemble ##
  cs_insn *instructions;
  size_t *instructions_total;
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
  // Assembler
  ks_engine *ks;
  // Capstone
  csh capstone;
  MiniKernel kernel;

  // Registers
  std::array<uint32_t, REGISTERS_TOTAL> registers;
  std::array<void *, REGISTERS_TOTAL> register_ptrs;

  // Memory
  std::array<uint8_t, MEMORY_SIZE> memory;
  // Stack pair<ADDRESS, VALUE>
  std::vector<std::pair<uint64_t, uint32_t>> stack;

  // ## TEMPO ##
  std::function<void(cs_insn *, size_t)> update_disassembler_fn;
  std::function<void(uint32_t)> update_pc_fn;
  Console *console;

  // ## Configuration ##
  uint32_t ESP_Address;
  uint32_t EBP_Address;
  uint32_t StartAddress;

  // ## ToDo: Move to Like ExecutableData struct or something ##
  uint64_t END_ADDRESS;

  EmulatorState();
  ~EmulatorState();

  // Run the emulator
  void run();
  // Step by Step
  void step();
  // Clear the state
  void reset();

  // ToDo: DISPLAY IF ASM CODE ERROR
  // ## Assemble & Disassemble ##
  void assemble(const char *value);
  void disassemble(const uint8_t *machine_code, size_t size, cs_insn **insn,
                   size_t *count) const;

  // ## Update the Registers & Stack ##
  void update_registers();
  void read_stack();
};

#endif /* EmulatorState_h */
