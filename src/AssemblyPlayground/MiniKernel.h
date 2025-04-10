//
//  MiniKernel.h
//  SimpleAssemblyPlayground
//
//  Created by MyzTyn on 2025/04/09.
//

#ifndef MiniKernel_h
#define MiniKernel_h

#include <functional>
#include <stdint.h>
#include <unordered_map>

// ToDo: Implement rest of the syscall handlers

// Forward declare EmulatorState
class EmulatorState;

// Define a type alias for the syscall handler function
using SyscallHandler = std::function<void(EmulatorState *)>;

class MiniKernel {
  std::unordered_map<uint32_t, SyscallHandler> syscall_handlers;

public:
  void default_linux_syscall();

  void register_syscall(uint32_t syscall_num, SyscallHandler handler) {
    syscall_handlers[syscall_num] = handler;
  }

  void handle_syscall(uint32_t syscall_num, EmulatorState *emulator_state);

private:
  // Handle Unknown syscalls
  void handle_unknown_syscall(uint32_t syscall_num, EmulatorState *state);
};

// ## Simple Linux Kernel (Syscall) ##

void handle_sys_write(EmulatorState *);
void handle_sys_read(EmulatorState *);
void handle_sys_exit(EmulatorState *);
void handle_sys_time(EmulatorState *);

#endif /* MiniKernel_h */
