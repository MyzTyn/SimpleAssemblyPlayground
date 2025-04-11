//
//  MiniKernel.h
//  SimpleAssemblyPlayground
//
//  Created by MyzTyn on 2025/04/09.
//

#ifndef MiniKernel_h
#define MiniKernel_h

#include <functional>
#include <cstdint>
#include <unordered_map>

// ToDo: Implement rest of the syscall handlers

// Forward declare EmulatorState
class EmulatorState;

// Define a type alias for the syscall handler function
using SyscallHandler = std::function<void(EmulatorState *)>;

class MiniKernel {
  std::unordered_map<uint32_t, SyscallHandler> syscall_handlers_;

public:
  void DefaultLinuxSyscall();

  void RegisterSyscall(const uint32_t syscall_num, const SyscallHandler & handler) {
    syscall_handlers_[syscall_num] = handler;
  }

  void HandleSyscall(uint32_t syscall_num, EmulatorState *emulator_state);

private:
  static void HandleUnknownSyscall(uint32_t syscall_num,
                                  const EmulatorState *state);
};

// ## Simple Linux Kernel (Syscall) ##

void handle_sys_write(EmulatorState *);
void handle_sys_read(EmulatorState *);
void handle_sys_exit(const EmulatorState *);
void handle_sys_time(EmulatorState *);

#endif /* MiniKernel_h */
