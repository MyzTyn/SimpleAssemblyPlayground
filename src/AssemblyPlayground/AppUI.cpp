//
//  AppUI.cpp
//  ia32_emulator
//
//  Created by MyzTyn on 2025/04/03.
//

#include "AppUI.h"

#include "imgui_stdlib.h"
#include "keystone/keystone.h"

#include "EmulatorState.h"

AssemblyCodeEditor::AssemblyCodeEditor()
    : default_eax_value_(0),
      default_ebx_value_(0),
      default_ecx_value_(0),
      default_edx_value_(0),
      default_esi_value_(0),
      default_edi_value_(0),
      default_eip_value_(0) {
  // Initialize Keystone assembler for 32-bit x86 (ATT syntax)
  if (ks_open(KS_ARCH_X86, KS_MODE_32, &keystone_engine_) != KS_ERR_OK) {
    throw std::runtime_error("Failed to initialize Keystone engine");
  }
  ks_option(keystone_engine_, KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT);
  // Initialize Capstone
  if (cs_open(CS_ARCH_X86, CS_MODE_32, &capstone_engine_) != CS_ERR_OK) {
    throw std::runtime_error("Failed to initialize Capstone engine");
  }
  cs_option(capstone_engine_, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);

  // Default Code (Preload)
  buffer_ = R"(.globl _main
_main:
    # Print "Hello World"
    movl    $1, %eax            # Syscall number for sys_write
    movl    $1, %ebx            # File descriptor 1 (stdout)
    movl    $str, %ecx          # Pointer to string
    movl    $0xD, %edx          # Length of string
    int     $0x80               # Invoke syscall

    pushl   $2                  # Push second argument (value 2)
    pushl   $4                  # Push first argument (value 4)
    call    sum                 # Call sum; return address pushed

    # Print the result
    addl $0x30, %eax
    movb %al, result+8

    # Print "Result: X\n"
    movl    $1, %eax            # Syscall number for sys_write
    movl    $1, %ebx            # File descriptor 1 (stdout)
    movl    $result, %ecx       # Pointer to result string
    movl    $0xA, %edx          # Length of string
    int     $0x80               # Invoke syscall

    movl    $0x3C, %eax         # Syscall number for exit
    xorl    %ebx, %ebx          # Exit code 0
    int     $0x80               # Exit syscall
sum:
    pushl   %ebp                # Save caller’s base pointer
    movl    %esp, %ebp          # Establish new stack frame

    movl    8(%ebp), %eax       # Load first argument (should be 4)
    movl    0xC(%ebp), %ebx     # Load second argument (should be 2)
    addl    %ebx, %eax          # EAX = 4 + 2 = 6

    movl    %ebp, %esp          # Restore ESP to the frame base
    popl    %ebp                # Restore caller’s base pointer
    ret                         # Return (pop return address into EIP)
str:
    .ascii "Hello World\n\0"
result:
    .ascii "Result:  \n"
)";
}

AssemblyCodeEditor::~AssemblyCodeEditor() {
  ks_close(keystone_engine_);
  cs_close(&capstone_engine_);
}

void AssemblyCodeEditor::Draw() {
  ImGui::Begin("Assembly Code Editor", nullptr, ImGuiWindowFlags_NoCollapse);

  // Optional: Give a small padding
  ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(2, 2));

  // Resize automatically with the window using child region
  ImVec2 content_region = ImGui::GetContentRegionAvail();
  ImGui::InputTextMultiline("##asm_editor", &buffer_,
                            ImVec2(content_region.x, content_region.y - 25));

  ImGui::PopStyleVar();

  // Align compile button to right
  ImGui::SetCursorPosX(ImGui::GetCursorPosX() + content_region.x -
                       100);  // 100 is button width
  if (ImGui::Button("Compile", ImVec2(100, 0))) {
    Compile();
  }

  ImGui::End();
}

void AssemblyCodeEditor::Compile() const {
  // compiled setup
  uint8_t *compiled_code;
  size_t compiled_size;
  size_t compiled_count;

  // Compile the ASM code
  if (ks_asm(keystone_engine_, buffer_.c_str(), default_start_address_,
             &compiled_code, &compiled_size, &compiled_count) != KS_ERR_OK) {
    // Use callback event to output the logs??
    // console->AddLog("ASM code failed to compile!");

    // Cleanup
    free(compiled_code);
    return;
  }

  // Disassemble setup
  cs_insn *instructions;
  const size_t instruction_size =
      cs_disasm(capstone_engine_, compiled_code, compiled_size,
                default_start_address_, 0, &instructions);

  if (instruction_size == 0) {
    free(compiled_code);
    free(instructions);
    return;
  }

  auto *executable_data = new ExecutableData();
  executable_data->default_eax_value = default_eax_value_;
  executable_data->default_ebx_value = default_ebx_value_;
  executable_data->default_ecx_value = default_ecx_value_;
  executable_data->default_edx_value = default_edx_value_;
  executable_data->default_esp_value = default_esp_value_;
  executable_data->default_ebp_value = default_ebp_value_;
  executable_data->default_esi_value = default_esi_value_;
  executable_data->default_edi_value = default_edi_value_;
  executable_data->default_eip_value = default_eip_value_;
  executable_data->default_start_address = default_start_address_;
  executable_data->default_end_address = default_start_address_ + compiled_size;

  // Copy the buffer
  executable_data->code = buffer_;
  // Set the BIN
  executable_data->bin = compiled_code;
  executable_data->bin_size = compiled_size;
  // Set the Disassemble
  executable_data->instructions = instructions;
  executable_data->instruction_size = instruction_size;

  on_compiled(executable_data);
}

Disassembler::~Disassembler() {
  if (instructions && instruction_count > 0)
    cs_free(instructions, instruction_count);
}

void Disassembler::Draw() const {
  ImGui::Begin("Disassembler");

  // Make the window larger by default for better visibility
  ImGui::SetWindowSize(ImVec2(600, 300), ImGuiCond_FirstUseEver);

  // Only draw if we have disassembled instructions
  if (instructions && instruction_count > 0) {
    // Use ImGui's clipper for large lists
    ImGuiListClipper clipper;

    // Display Buttons
    if (ImGui::SmallButton("Run")) {
      if (run_fn) {
        run_fn();
      }
    }
    ImGui::SameLine();

    if (ImGui::SmallButton("Step")) {
      if (step_fn) {
        step_fn();
      }
    }
    ImGui::SameLine();

    if (ImGui::SmallButton("Reset")) {
      if (reset_fn) {
        reset_fn();
      }
    }

    ImGui::Separator();

    // Create a child window for scrolling with visible border
    ImGui::BeginChild("##disassembly", ImVec2(0, 0), true,
                      ImGuiWindowFlags_HorizontalScrollbar);

    // Make text bigger for better visibility
    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[0]);
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(4, 8));

    clipper.Begin(static_cast<int>(instruction_count));

    while (clipper.Step()) {
      for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
        cs_insn &insn = instructions[i];
        bool is_current_pc = (insn.address == current_pc);

        // Create a unique ID for this line
        ImGui::PushID(static_cast<int>(insn.address));

        // Selectable row
        //                bool is_selected = (selected_address == insn.address);
        bool is_selected = false;
        if (ImGui::Selectable("##line", is_selected,
                              ImGuiSelectableFlags_AllowDoubleClick |
                                  ImGuiSelectableFlags_SpanAllColumns,
                              ImVec2(0, ImGui::GetTextLineHeight() * 1.5F))) {
          //                    selected_address = is_selected ? -1 :
          //                    insn.address;
          if (ImGui::IsMouseDoubleClicked(0)) {
            //                        ToggleBreakpoint(insn.address);
          }
        }

        // Right-click context menu
        if (ImGui::BeginPopupContextItem("DisassemblyContextMenu")) {
          if (ImGui::MenuItem("Toggle Breakpoint")) {
            //                        ToggleBreakpoint(insn.address);
          }
          if (ImGui::MenuItem("Copy Address")) {
            char buf[16];
            snprintf(buf, sizeof(buf), "0x%llX",
                     (long long unsigned)insn.address);
            ImGui::SetClipboardText(buf);
          }
          ImGui::EndPopup();
        }

        // Highlighting
        if (is_selected) {
          ImGui::SetItemDefaultFocus();
          ImGui::GetWindowDrawList()->AddRectFilled(
              ImGui::GetItemRectMin(), ImGui::GetItemRectMax(),
              ImGui::GetColorU32(ImGuiCol_HeaderActive));
        }
        //                else if (HasBreakpoint(insn.address)) {
        //                    ImGui::GetWindowDrawList()->AddRectFilled(
        //                        ImGui::GetItemRectMin(),
        //                        ImGui::GetItemRectMax(),
        //                        ImGui::GetColorU32(ImVec4(0.8f, 0.1f, 0.1f,
        //                        0.3f))
        //                    );
        //                }
        else if (is_current_pc) {
          ImGui::GetWindowDrawList()->AddRectFilled(
              ImGui::GetItemRectMin(), ImGui::GetItemRectMax(),
              ImGui::GetColorU32(ImVec4(0.8f, 0.8f, 0.1f, 0.3f)));
        }

        // Format the bytes as a string
        char bytes_str[50] = {};
        for (int j = 0; j < insn.size; j++) {
          char byte_str[4];
          snprintf(byte_str, sizeof(byte_str), "%02X ", insn.bytes[j]);
          strcat(bytes_str, byte_str);
        }

        // ## Memory Address
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(0.2F, 0.8F, 1.0F, 1.0F), "0x%llX",
                           insn.address);

        // ## PC ICON
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(1.0F, 1.0F, 0.0F, 1.0F),
                           is_current_pc ? "->" : "  ");

        // ## Instruction
        ImGui::SameLine();
        ImGui::TextColored(is_current_pc ? ImVec4(1.0F, 1.0F, 0.0F, 1.0F)
                                         : ImVec4(1.0F, 1.0F, 1.0F, 1.0F),
                           "%s %s", insn.mnemonic, insn.op_str);

        // ## Raw code
        ImGui::SameLine();
        ImGui::TextDisabled("; %s", bytes_str);

        ImGui::PopID();
      }
    }

    ImGui::PopStyleVar();
    ImGui::PopFont();
    ImGui::EndChild();
  } else {
    ImGui::Text("No instructions disassembled");
  }

  ImGui::End();
}

Console::Console() {
  ClearLog();
  memset(InputBuf, 0, sizeof(InputBuf));
  HistoryPos = -1;

  // "CLASSIFY" is here to provide the test case where "C"+[tab] completes to
  // "CL" and display multiple matches.
  Commands.push_back("HELP");
  Commands.push_back("HISTORY");
  Commands.push_back("CLEAR");
  Commands.push_back("CLASSIFY");
  AutoScroll = true;
  ScrollToBottom = false;
}

Console::~Console() {
  ClearLog();
  for (int i = 0; i < History.Size; i++) ImGui::MemFree(History[i]);
}

void Console::ClearLog() {
  for (int i = 0; i < Items.Size; i++) ImGui::MemFree(Items[i]);
  Items.clear();
}

void Console::AddLog(const char *fmt, ...) {
  // FIXME-OPT
  char buf[1024];
  va_list args;
  va_start(args, fmt);
  vsnprintf(buf, IM_ARRAYSIZE(buf), fmt, args);
  buf[IM_ARRAYSIZE(buf) - 1] = 0;
  va_end(args);
  Items.push_back(Strdup(buf));
}

void Console::Draw(const char *title) {
  ImGui::SetNextWindowSize(ImVec2(520, 600), ImGuiCond_FirstUseEver);

  ImGui::Begin(title);

  // TODO: display items starting from the bottom

  //    if (ImGui::SmallButton("Add Debug Text"))  { AddLog("%d some text",
  //    Items.Size); AddLog("some more text"); AddLog("display very important
  //    message here!"); } ImGui::SameLine(); if (ImGui::SmallButton("Add Debug
  //    Error")) { AddLog("[error] something went wrong"); } ImGui::SameLine();
  //    if (ImGui::SmallButton("Clear"))           { ClearLog(); }
  //    ImGui::SameLine();
  //    bool copy_to_clipboard = ImGui::SmallButton("Copy");
  // static float t = 0.0f; if (ImGui::GetTime() - t > 0.02f) { t =
  // ImGui::GetTime(); AddLog("Spam %f", t); }

  ImGui::Separator();

  // Options menu
  if (ImGui::BeginPopup("Options")) {
    ImGui::Checkbox("Auto-scroll", &AutoScroll);
    ImGui::EndPopup();
  }

  // Options, Filter
  ImGui::SetNextItemShortcut(ImGuiMod_Ctrl | ImGuiKey_O,
                             ImGuiInputFlags_Tooltip);
  if (ImGui::Button("Options")) ImGui::OpenPopup("Options");
  ImGui::SameLine();
  Filter.Draw(R"(Filter ("incl,-excl") ("error"))", 180);
  ImGui::Separator();

  // Reserve enough left-over height for 1 separator + 1 input text
  const float footer_height_to_reserve =
      ImGui::GetStyle().ItemSpacing.y + ImGui::GetFrameHeightWithSpacing();
  if (ImGui::BeginChild("ScrollingRegion", ImVec2(0, -footer_height_to_reserve),
                        ImGuiChildFlags_NavFlattened,
                        ImGuiWindowFlags_HorizontalScrollbar)) {
    if (ImGui::BeginPopupContextWindow()) {
      if (ImGui::Selectable("Clear")) ClearLog();
      ImGui::EndPopup();
    }

    // Display every line as a separate entry so we can change their color or
    // add custom widgets. If you only want raw text you can use
    // ImGui::TextUnformatted(log.begin(), log.end()); NB- if you have thousands
    // of entries this approach may be too inefficient and may require user-side
    // clipping to only process visible items. The clipper will automatically
    // measure the height of your first item and then "seek" to display only
    // items in the visible area. To use the clipper we can replace your
    // standard loop:
    //      for (int i = 0; i < Items.Size; i++)
    //   With:
    //      ImGuiListClipper clipper;
    //      clipper.Begin(Items.Size);
    //      while (clipper.Step())
    //         for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++)
    // - That your items are evenly spaced (same height)
    // - That you have cheap random access to your elements (you can access them
    // given their index,
    //   without processing all the ones before)
    // You cannot this code as-is if a filter is active because it breaks the
    // 'cheap random-access' property. We would need random-access on the
    // post-filtered list. A typical application wanting coarse clipping and
    // filtering may want to pre-compute an array of indices or offsets of items
    // that passed the filtering test, recomputing this array when user changes
    // the filter, and appending newly elements as they are inserted. This is
    // left as a task to the user until we can manage to improve this example
    // code! If your items are of variable height:
    // - Split them into same height items would be simpler and facilitate
    // random-seeking into your list.
    // - Consider using manual call to IsRectVisible() and skipping extraneous
    // decoration from your items.
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing,
                        ImVec2(4, 1));  // Tighten spacing
                                        //        if (copy_to_clipboard)
                                        //            ImGui::LogToClipboard();
    for (const char *item : Items) {
      if (!Filter.PassFilter(item)) continue;

      // Normally you would store more information in your item than just a
      // string. (e.g. make Items[] an array of structure, store color/type
      // etc.)
      ImVec4 color;
      bool has_color = false;
      if (strstr(item, "[error]")) {
        color = ImVec4(1.0F, 0.4F, 0.4F, 1.0F);
        has_color = true;
      } else if (strncmp(item, "# ", 2) == 0) {
        color = ImVec4(1.0F, 0.8F, 0.6F, 1.0F);
        has_color = true;
      }
      if (has_color) ImGui::PushStyleColor(ImGuiCol_Text, color);
      ImGui::TextUnformatted(item);
      if (has_color) ImGui::PopStyleColor();
    }
    //        if (copy_to_clipboard)
    //            ImGui::LogFinish();

    // Keep up at the bottom of the scroll region if we were already at the
    // bottom at the beginning of the frame. Using a scrollbar or mouse-wheel
    // will take away from the bottom edge.
    if (ScrollToBottom ||
        (AutoScroll && ImGui::GetScrollY() >= ImGui::GetScrollMaxY()))
      ImGui::SetScrollHereY(1.0f);
    ScrollToBottom = false;

    ImGui::PopStyleVar();
  }
  ImGui::EndChild();
  ImGui::Separator();

  // Command-line
  bool reclaim_focus = false;
  ImGuiInputTextFlags input_text_flags =
      ImGuiInputTextFlags_EnterReturnsTrue |
      ImGuiInputTextFlags_EscapeClearsAll |
      ImGuiInputTextFlags_CallbackCompletion |
      ImGuiInputTextFlags_CallbackHistory;
  if (ImGui::InputText("Input", InputBuf, IM_ARRAYSIZE(InputBuf),
                       input_text_flags, &TextEditCallbackStub, this)) {
    char *s = InputBuf;
    Strtrim(s);
    if (s[0]) ExecCommand(s);
    strcpy(s, "");
    reclaim_focus = true;
  }

  // Auto-focus on window apparition
  ImGui::SetItemDefaultFocus();
  if (reclaim_focus)
    ImGui::SetKeyboardFocusHere(-1);  // Auto focus previous widget

  ImGui::End();
}

void Console::ExecCommand(const char *command_line) {
  AddLog("# %s\n", command_line);

  // Insert into history. First find match and delete it so it can be pushed to
  // the back. This isn't trying to be smart or optimal.
  //    HistoryPos = -1;
  //    for (int i = History.Size - 1; i >= 0; i--)
  //        if (Stricmp(History[i], command_line) == 0)
  //        {
  //            ImGui::MemFree(History[i]);
  //            History.erase(History.begin() + i);
  //            break;
  //        }
  //    History.push_back(Strdup(command_line));

  // Process command
  if (Stricmp(command_line, "CLEAR") == 0) {
    ClearLog();
  }
  //    else if (Stricmp(command_line, "HELP") == 0)
  //    {
  //        AddLog("Commands:");
  //        for (int i = 0; i < Commands.Size; i++)
  //            AddLog("- %s", Commands[i]);
  //    }
  //    else if (Stricmp(command_line, "HISTORY") == 0)
  //    {
  //        int first = History.Size - 10;
  //        for (int i = first > 0 ? first : 0; i < History.Size; i++)
  //            AddLog("%3d: %s\n", i, History[i]);
  //    }
  else {
    AddLog("Unknown command: '%s'\n", command_line);
  }

  // On command input, we scroll to bottom even if AutoScroll==false
  ScrollToBottom = true;
}

int Console::TextEditCallback(ImGuiInputTextCallbackData *data) {
  // AddLog("cursor: %d, selection: %d-%d", data->CursorPos,
  // data->SelectionStart, data->SelectionEnd);
  switch (data->EventFlag) {
    case ImGuiInputTextFlags_CallbackCompletion: {
      // Example of TEXT COMPLETION

      // Locate beginning of current word
      const char *word_end = data->Buf + data->CursorPos;
      const char *word_start = word_end;
      while (word_start > data->Buf) {
        const char c = word_start[-1];
        if (c == ' ' || c == '\t' || c == ',' || c == ';') break;
        word_start--;
      }

      // Build a list of candidates
      ImVector<const char *> candidates;
      for (int i = 0; i < Commands.Size; i++)
        if (Strnicmp(Commands[i], word_start, (int)(word_end - word_start)) ==
            0)
          candidates.push_back(Commands[i]);

      if (candidates.Size == 0) {
        // No match
        AddLog("No match for \"%.*s\"!\n", (int)(word_end - word_start),
               word_start);
      } else if (candidates.Size == 1) {
        // Single match. Delete the beginning of the word and replace it
        // entirely so we've got nice casing.
        data->DeleteChars((int)(word_start - data->Buf),
                          (int)(word_end - word_start));
        data->InsertChars(data->CursorPos, candidates[0]);
        data->InsertChars(data->CursorPos, " ");
      } else {
        // Multiple matches. Complete as much as we can..
        // So inputting "C"+Tab will complete to "CL" then display "CLEAR" and
        // "CLASSIFY" as matches.
        int match_len = (int)(word_end - word_start);
        for (;;) {
          int c = 0;
          bool all_candidates_matches = true;
          for (int i = 0; i < candidates.Size && all_candidates_matches; i++)
            if (i == 0)
              c = toupper(candidates[i][match_len]);
            else if (c == 0 || c != toupper(candidates[i][match_len]))
              all_candidates_matches = false;
          if (!all_candidates_matches) break;
          match_len++;
        }

        if (match_len > 0) {
          data->DeleteChars((int)(word_start - data->Buf),
                            (int)(word_end - word_start));
          data->InsertChars(data->CursorPos, candidates[0],
                            candidates[0] + match_len);
        }

        // List matches
        AddLog("Possible matches:\n");
        for (int i = 0; i < candidates.Size; i++)
          AddLog("- %s\n", candidates[i]);
      }

      break;
    }
    case ImGuiInputTextFlags_CallbackHistory: {
      // Example of HISTORY
      const int prev_history_pos = HistoryPos;
      if (data->EventKey == ImGuiKey_UpArrow) {
        if (HistoryPos == -1)
          HistoryPos = History.Size - 1;
        else if (HistoryPos > 0)
          HistoryPos--;
      } else if (data->EventKey == ImGuiKey_DownArrow) {
        if (HistoryPos != -1)
          if (++HistoryPos >= History.Size) HistoryPos = -1;
      }

      // A better implementation would preserve the data on the current input
      // line along with cursor position.
      if (prev_history_pos != HistoryPos) {
        const char *history_str = (HistoryPos >= 0) ? History[HistoryPos] : "";
        data->DeleteChars(0, data->BufTextLen);
        data->InsertChars(0, history_str);
      }
    }
  }
  return 0;
}
