//
//  EmulatorState.cpp
//  SimpleAssemblyPlayground
//
//  Created by MyzTyn on 2025/04/07.
//

#include "EmulatorState.h"

#include <algorithm>
#include <stdexcept>

#include "unicorn/unicorn.h"

#include "Console.h"

// ToDo: Turn into class or enum (Aka helper function to easily write/read rather than access by index)
static int reg_ids[] = {UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX,
                 UC_X86_REG_EDX, UC_X86_REG_ESP, UC_X86_REG_EBP,
                 UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EIP};

// Hook to catch syscalls (Simple Kernel)
static void hook_syscall(uc_engine *uc, uint32_t intno, void *user_data) {
  auto *emulator_state = static_cast<EmulatorState *>(user_data);
  // Update the registers
  emulator_state->update_registers();
  emulator_state->kernel.HandleSyscall(emulator_state->registers[0],
                                       emulator_state);
}

// Hook for Breakpoints
static void hook_breakpoint(uc_engine *uc, uint64_t address, uint32_t size,
                            void *user_data) {
  auto *emulator_state = static_cast<EmulatorState *>(user_data);
  // Update the registers
  emulator_state->update_registers();
  if (emulator_state->has_breakpoint(emulator_state->registers[8])) {
    uc_emu_stop(emulator_state->uc);
  }
}

EmulatorState::EmulatorState()
    : uc(nullptr),
      registers{},
      register_ptrs{},
      memory{},
      executable_data(nullptr) {
  // Initialize Unicorn engine
  if (uc_open(UC_ARCH_X86, UC_MODE_32, &uc) != UC_ERR_OK) {
    throw std::runtime_error("Failed to initialize Unicorn engine!");
  }

  // Register the system call
  uc_hook syscall;
  uc_hook_add(uc, &syscall, UC_HOOK_INTR, (void *)hook_syscall, this, 0, 0);
  uc_hook breakpoint;
  uc_hook_add(uc, &breakpoint, UC_HOOK_CODE, (void *)hook_breakpoint, this, 0,
              UINT64_MAX);

  // Assign each element of ptrs to point to the corresponding reg_values
  for (int i = 0; i < REGISTERS_TOTAL; i++) {
    register_ptrs[i] = &registers[i];  // Store addresses of each element
  }

  // Map the memory
  if (uc_mem_map_ptr(uc, 0, MEMORY_SIZE, UC_PROT_ALL, memory.data()) !=
      UC_ERR_OK) {
    throw std::runtime_error("Failed to map the memory");
  }

  stack.reserve(10);
  stack.clear();

  // Load the default syscalls
  kernel.DefaultLinuxSyscall();
}

EmulatorState::~EmulatorState() {
  uc_close(uc);
  delete executable_data;
}

// run to the end
void EmulatorState::run() {
  reset();

  // Start the cpu
  uc_emu_start(uc, executable_data->default_start_address, executable_data->default_end_address, 0, 0);
  update_registers();
  read_stack();
}

void EmulatorState::step() {
  uc_emu_start(uc, registers[8], executable_data->default_end_address, 0, 1);
  update_registers();
  read_stack();
}

// clear the state
void EmulatorState::reset() {
  // Clear and setup the registers
  registers[0] = executable_data->default_eax_value;
  registers[1] = executable_data->default_ebx_value;
  registers[2] = executable_data->default_ecx_value;
  registers[3] = executable_data->default_edx_value;
  registers[4] = executable_data->default_esp_value;
  registers[5] = executable_data->default_ebp_value;
  registers[6] = executable_data->default_esi_value;
  registers[7] = executable_data->default_edi_value;
  registers[8] = executable_data->default_start_address;
  registers[9] = executable_data->default_eip_value;

  uc_reg_write_batch(uc, reg_ids, register_ptrs.data(), REGISTERS_TOTAL);
  // Clear the cache (Seems fixed the bug: run once then step fn would act like
  // run rather than step by step behaviour)
  uc_ctl_remove_cache(uc, executable_data->default_start_address, MEMORY_SIZE);
  // Update it
  update_pc_fn(executable_data->default_start_address);
  read_stack();
}

void EmulatorState::update_registers() {
  uc_reg_read_batch(uc, reg_ids, register_ptrs.data(), REGISTERS_TOTAL);
  update_pc_fn(registers[8]);
}

void EmulatorState::read_stack() {
  const size_t size = executable_data->default_esp_value - registers[4];
  stack.clear();

  if (size == 0) {
    return;
  }

  for (uint32_t addr = registers[4]; addr < executable_data->default_ebp_value; addr += 4) {
    uint32_t value = *reinterpret_cast<uint32_t *>(&memory[addr]);
    stack.emplace_back(addr, value);
  }
}
