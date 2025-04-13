//
//  MiniKernel.c
//  SimpleAssemblyPlayground
//
//  Created by MyzTyn on 2025/04/09.
//

#include "MiniKernel.h"

#include <ctime>

#include "unicorn/unicorn.h"

#include "EmulatorState.h"
#include "Console.h"

// Linux Syscall table https://filippo.io/linux-syscall-table/
void MiniKernel::DefaultLinuxSyscall() {
  RegisterSyscall(0x01, handle_sys_write);
  RegisterSyscall(0x3C, handle_sys_exit);
  RegisterSyscall(0xC9, handle_sys_time);
}

void MiniKernel::HandleUnknownSyscall(const uint32_t syscall_num,
                                      const EmulatorState *state) {
  Console::Instance().AddLog("[SYSCALL] Unknown syscall: %d\n", syscall_num);
}

void MiniKernel::HandleSyscall(const uint32_t syscall_num,
                               EmulatorState *emulator_state) {
  const auto it = syscall_handlers_.find(syscall_num);
  if (it != syscall_handlers_.end()) {
    it->second(emulator_state);
  } else {
    HandleUnknownSyscall(syscall_num,
                         emulator_state);
  }
}

void handle_sys_read(EmulatorState *) {
  // Use Console to read the input?
}

void handle_sys_write(EmulatorState *emulator_state) {
  const uint32_t fd = emulator_state->registers[1];   // EBX (file descriptor)
  const uint32_t buf = emulator_state->registers[2];  // ECX (buffer address)
  const uint32_t len = emulator_state->registers[3];  // EDX (length)

  // Directly reference emulator state memory
  char *data = reinterpret_cast<char *>(&emulator_state->memory[buf]);

  // Output
  Console::Instance().AddLog("%.*s", len, data);
}

void handle_sys_exit(const EmulatorState *emulator_state) {
  const uint32_t exit_code = emulator_state->registers[1];  // EBX (exit code)
  Console::Instance().AddLog("Program exited: %d", exit_code);

  uc_emu_stop(emulator_state->uc);  // Stop the emulation
}

void handle_sys_time(EmulatorState *emulator_state) {
  const std::time_t time = std::time(nullptr);
  emulator_state->registers[0] = static_cast<uint32_t>(time);
  Console::Instance().AddLog("[SYSCALL]: sys_time: %ld", time);
}
