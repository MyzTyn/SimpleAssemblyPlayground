//
//  AppUI.cpp
//  SimpleAssemblyPlayground
//
//  Created by MyzTyn on 2025/04/03.
//

#include "AppUI.h"

#include <stdexcept>

#include "imgui_stdlib.h"
#include "keystone/keystone.h"

#include "EmulatorState.h"
#include "Console.h"

AssemblyCodeEditor::AssemblyCodeEditor()
    : default_eax_value_(0),
      default_ebx_value_(0),
      default_ecx_value_(0),
      default_edx_value_(0),
      default_esp_value_(0x1500),
      default_ebp_value_(0x1500),
      default_esi_value_(0),
      default_edi_value_(0),
      default_eip_value_(0),
      default_start_address_(0x200) {
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

  // Make the window larger by default for better visibility
  ImGui::SetWindowSize(ImVec2(600, 300), ImGuiCond_FirstUseEver);

  // Optional: Give a small padding
  ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(2, 2));

  // Resize automatically with the window using child region
  ImVec2 content_region = ImGui::GetContentRegionAvail();
  ImGui::InputTextMultiline("##asm_editor", &buffer_,
                            ImVec2(content_region.x, content_region.y - 25));

  ImGui::PopStyleVar();

  // Align compile button to right
  ImGui::SetCursorPosX(ImGui::GetCursorPosX() + content_region.x - 100);  // 100 is button width
  if (ImGui::Button("Compile", ImVec2(100, 0))) {
    Compile();
  }

  ImGui::End();
}

void AssemblyCodeEditor::Compile() const {
  // Prevent from recompiling twice
  if (on_duplicate_check(buffer_.c_str())) {
    return;
  }

  // compiled setup
  uint8_t *compiled_code;
  size_t compiled_size;
  size_t compiled_count;

  // Compile the ASM code
  if (ks_asm(keystone_engine_, buffer_.c_str(), default_start_address_,
             &compiled_code, &compiled_size, &compiled_count) != KS_ERR_OK) {
    // Use callback event to output the logs??
    Console::Instance().AddLog("ASM code failed to compile!");

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
