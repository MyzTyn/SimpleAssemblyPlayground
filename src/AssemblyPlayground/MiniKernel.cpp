//
//  MiniKernel.c
//  SimpleAssemblyPlayground
//
//  Created by MyzTyn on 2025/04/09.
//

#include "MiniKernel.h"

#include "unicorn/unicorn.h"
#include <ctime>

#include "EmulatorState.h"

// Linux Syscall table https://filippo.io/linux-syscall-table/
void MiniKernel::default_linux_syscall() {
  register_syscall(0x01, handle_sys_write);
  register_syscall(0x3C, handle_sys_exit);
  register_syscall(0xC9, handle_sys_time);
}

void MiniKernel::handle_unknown_syscall(uint32_t syscall_num,
                                        EmulatorState *state) {
  state->console->AddLog("[SYSCALL] Unknown syscall: %d\n", syscall_num);
}

void MiniKernel::handle_syscall(uint32_t syscall_num,
                                EmulatorState *emulator_state) {
  auto it = syscall_handlers.find(syscall_num);
  if (it != syscall_handlers.end()) {
    it->second(emulator_state); // Call the handler
  } else {
    handle_unknown_syscall(syscall_num,
                           emulator_state); // Handle unknown syscalls
  }
}

void handle_sys_read(EmulatorState *) {
  // Use Console to read the input?
}

void handle_sys_write(EmulatorState *emulator_state) {
  uint32_t fd = emulator_state->registers[1];  // EBX (file descriptor)
  uint32_t buf = emulator_state->registers[2]; // ECX (buffer address)
  uint32_t len = emulator_state->registers[3]; // EDX (length)

  // Directly reference emulator state memory
  char *data = reinterpret_cast<char *>(&emulator_state->memory[buf]);

  // Output
  emulator_state->console->AddLog("%.*s", len, data);
}

void handle_sys_exit(EmulatorState *emulator_state) {
  uint32_t exit_code = emulator_state->registers[1]; // EBX (exit code)
  emulator_state->console->AddLog("Program exited: %d", exit_code);

  uc_emu_stop(emulator_state->uc); // Stop the emulation
}

void handle_sys_time(EmulatorState *emulator_state) {
  std::time_t time = std::time(nullptr);
  emulator_state->registers[0] = static_cast<uint32_t>(time);
  emulator_state->console->AddLog("[SYSCALL]: sys_time: %ld", time);
}
