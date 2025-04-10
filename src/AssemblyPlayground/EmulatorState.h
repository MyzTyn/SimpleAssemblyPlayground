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
#include <stdio.h>
#include <vector>

#include "capstone/capstone.h"
#include "keystone/keystone.h"
#include "unicorn/unicorn.h"

#include "AppUI.h"
#include "MiniKernel.h"

#define MEMSIZE 0x2000
#define REG_TOTAL 9

// ToDo: Remove the TEMPO and use bool based (state) to fetch any latest data

struct ExecutableData {
  // ## Configuration ##
  uint32_t ESP_Address;
  uint32_t EBP_Address;
  uint32_t StartAddress;
  uint64_t END_ADDRESS;
  // Assembly Code
  char *code;

  // ## Bin ##
  uint8_t *bin;
  size_t bin_size;

  // ## Disassemble ##
  cs_insn *insns;
  size_t *total_insns;
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
  std::array<uint32_t, REG_TOTAL> registers;
  std::array<void *, REG_TOTAL> registeres_ptrs;

  // Memory
  std::array<uint8_t, MEMSIZE> memory;
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
  void disassemble(uint8_t *machine_code, size_t size, cs_insn **insn,
                   size_t *count);

  // ## Update the Registers & Stack ##
  void update_registers();
  void read_stack();
};

#endif /* EmulatorState_h */
