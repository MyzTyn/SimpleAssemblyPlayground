//
//  AppUI.h
//  ia32_emulator
//
//  Created by MyzTyn on 2025/04/03.
//

#ifndef AppUI_h
#define AppUI_h

#include <ctype.h>
#include <functional>
#include <stdio.h>

#include "capstone/capstone.h"
#include "imgui.h"

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

  void Draw();
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
    size_t len = strlen(s) + 1;
    void *buf = ImGui::MemAlloc(len);
    IM_ASSERT(buf);
    return (char *)memcpy(buf, (const void *)s, len);
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
    Console *console = (Console *)data->UserData;
    return console->TextEditCallback(data);
  }

  int TextEditCallback(ImGuiInputTextCallbackData *data);
};

#endif /* AppUI_h */
