//
//  MiniKernel.c
//  SimpleAssemblyPlayground
//
//  Created by MyzTyn on 2025/04/09.
//

#include "MiniKernel.h"

#include "EmulatorState.h"

#include "unicorn/unicorn.h"

void MiniKernel::default_linux_syscall() {
    register_syscall(0x01, handle_sys_exit);
    register_syscall(0x04, handle_sys_write);
}

void MiniKernel::handle_unknown_syscall(uint32_t syscall_num, EmulatorState* state) {
    state->console->AddLog("[SYSCALL] Unknown syscall: %d\n", syscall_num);
}

void handle_sys_write(EmulatorState *emulator_state) {
    uint32_t fd = emulator_state->registers[1];  // EBX (file descriptor)
    uint32_t buf = emulator_state->registers[2]; // ECX (buffer address)
    uint32_t len = emulator_state->registers[3]; // EDX (length)
    
    // Directly reference emulator state memory
    char* data = reinterpret_cast<char*>(&emulator_state->memory[buf]);
    
    // Output
    emulator_state->console->AddLog("%.*s", len, data);
}

void handle_sys_exit(EmulatorState* emulator_state) {
    uint32_t exit_code = emulator_state->registers[1]; // EBX (exit code)
    emulator_state->console->AddLog("Program exited: %d", exit_code);
    
    uc_emu_stop(emulator_state->uc); // Stop the emulation
}
