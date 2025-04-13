//
//  AppUI.h
//  ia32_emulator
//
//  Created by MyzTyn on 2025/04/03.
//

#ifndef AppUI_h
#define AppUI_h

#include <cctype>
#include <functional>

#include "capstone/capstone.h"
#include "imgui.h"
#include "keystone/keystone.h"

struct ExecutableData;

// Simple Assembly Code Editor Window
class  AssemblyCodeEditor {
  std::string buffer_;
  ks_engine *keystone_engine_;
  csh capstone_engine_;

  // ## Configable ##
  uint32_t default_eax_value_;
  uint32_t default_ebx_value_;
  uint32_t default_ecx_value_;
  uint32_t default_edx_value_;
  uint32_t default_esp_value_ = 0x1500;
  uint32_t default_ebp_value_ = 0x1500;
  uint32_t default_esi_value_;
  uint32_t default_edi_value_;
  uint32_t default_eip_value_;
  uint32_t default_start_address_ = 0x200;
  // uint64_t default_end_address_;
public:
  // Callback Event
  std::function<void(const ExecutableData*)> on_compiled;

  AssemblyCodeEditor();
  ~AssemblyCodeEditor();

  void Draw();
  void Compile();
};

// Simple Disassembly UI Window
struct Disassembler {
  cs_insn *instructions;
  size_t instruction_count;
  uint32_t current_pc;

  // Tempo (Rework)
  std::function<void()> run_fn;
  std::function<void()> step_fn;
  std::function<void()> reset_fn;

  Disassembler() = default;
  ~Disassembler();

  void Draw() const;
};

// Simple Console Window
struct Console {
  char InputBuf[256];
  ImVector<char *> Items;
  ImVector<const char *> Commands;
  ImVector<char *> History;
  int HistoryPos; // -1: new line, 0..History.Size-1 browsing history.
  ImGuiTextFilter Filter;
  bool AutoScroll;
  bool ScrollToBottom;

  Console();
  ~Console();

  // Portable helpers
  static int Stricmp(const char *s1, const char *s2) {
    int d;
    while ((d = toupper(*s2) - toupper(*s1)) == 0 && *s1) {
      s1++;
      s2++;
    }
    return d;
  }
  static int Strnicmp(const char *s1, const char *s2, int n) {
    int d = 0;
    while (n > 0 && (d = toupper(*s2) - toupper(*s1)) == 0 && *s1) {
      s1++;
      s2++;
      n--;
    }
    return d;
  }
  static char *Strdup(const char *s) {
    IM_ASSERT(s);
    const size_t len = strlen(s) + 1;
    void *buf = ImGui::MemAlloc(len);
    IM_ASSERT(buf);
    return static_cast<char *>(memcpy(buf, s, len));
  }
  static void Strtrim(char *s) {
    char *str_end = s + strlen(s);
    while (str_end > s && str_end[-1] == ' ')
      str_end--;
    *str_end = 0;
  }

  void ClearLog();

  void AddLog(const char *fmt, ...) IM_FMTARGS(2);

  void Draw(const char *title);

  void ExecCommand(const char *command_line);

  // In C++11 you'd be better off using lambdas for this sort of forwarding
  // callbacks
  static int TextEditCallbackStub(ImGuiInputTextCallbackData *data) {
    auto *console = static_cast<Console *>(data->UserData);
    return console->TextEditCallback(data);
  }

  int TextEditCallback(ImGuiInputTextCallbackData *data);
};

#endif /* AppUI_h */
