//
//  AppUI.h
//  SimpleAssemblyPlayground
//
//  Created by MyzTyn on 2025/04/03.
//

#ifndef AppUI_h
#define AppUI_h

#include <cctype>
#include <functional>
#include <string>
#include <unordered_map>

#include "capstone/capstone.h"
#include "keystone/keystone.h"

struct ExecutableData;

// Simple Assembly Code Editor Window
class AssemblyCodeEditor {
  std::string buffer_;
  ks_engine *keystone_engine_;
  csh capstone_engine_;

  // ## Configable ##
  uint32_t default_eax_value_;
  uint32_t default_ebx_value_;
  uint32_t default_ecx_value_;
  uint32_t default_edx_value_;
  uint32_t default_esp_value_;
  uint32_t default_ebp_value_;
  uint32_t default_esi_value_;
  uint32_t default_edi_value_;
  // uint32_t default_eip_value_;
  uint32_t default_start_address_;
  // uint64_t default_end_address_;
 public:
  // Callback Event
  std::function<bool(const char *)> on_duplicate_check;
  std::function<void(const ExecutableData *)> on_compiled;

  AssemblyCodeEditor();
  ~AssemblyCodeEditor();

  void Draw();
  void Compile() const;
};

// Simple Disassembly UI Window
struct Disassembler {
  // Use ExecutableData?
  cs_insn *instructions;
  size_t instruction_count;
  uint32_t current_pc;
  bool auto_scroll = true;

  std::unordered_map<uint64_t, bool> breakpoints;

  // Callback Events
  std::function<void()> run_fn;
  std::function<void()> step_fn;
  std::function<void()> reset_fn;

  Disassembler() = default;
  ~Disassembler() = default;

  void ToggleBreakpoint(uint64_t address) {
    breakpoints[address] = !breakpoints[address];
  }

  void Draw();
};

#endif /* AppUI_h */
