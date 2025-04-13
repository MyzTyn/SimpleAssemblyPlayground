//
//  app.cpp
//  ia32_emulator
//
//  Created by MyzTyn on 2025/03/26.
//

#include "app.h"
#include <array>
#include <imgui.h>
#include <stdexcept>
#include <string>
#include <vector>

#include "imgui_memory_editor.h"

#include "capstone/capstone.h"
#include "keystone/keystone.h"
#include "unicorn/unicorn.h"

#include "AppUI.h"
#include "EmulatorState.h"

// ToDo: Breakpoints
// ToDo: Redesign the Assembly Editor
// ToDo: Redo the code for safety
// ToDo: Create struct for ExecutableData (To avoid recompile twice)

static char assembly_code[1024 * 10] =
    R"(.globl _main
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

static Console console;
static AssemblyCodeEditor assembly_editor;
static Disassembler disassembler;
static MemoryEditor mem_edit;

// Register names
const char *reg_names[] = {"EAX", "EBX", "ECX", "EDX", "ESP",
                           "EBP", "ESI", "EDI", "EIP"};

static EmulatorState *emulator_state;

Application::Application() : io(ImGui::GetIO()) {
  io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
  io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
  //    io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;

  ImGui::StyleColorsDark();
  ImGuiStyle &style = ImGui::GetStyle();
  if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable) {
    style.WindowRounding = 0.0f;
    style.Colors[ImGuiCol_WindowBg].w = 1.0f;
  }

  // Setup
  emulator_state = new EmulatorState();
  emulator_state->console = &console;

  // Event callback (Remove those)
  emulator_state->update_disassembler_fn = [](cs_insn *instructions,
                                              size_t count) {
    disassembler.instructions = instructions;
    disassembler.instruction_count = count;
  };
  emulator_state->update_pc_fn = [](uint32_t pc) {
    disassembler.current_pc = pc;
  };
  disassembler.run_fn = []() { emulator_state->run(); };
  disassembler.step_fn = []() { emulator_state->step(); };
  disassembler.reset_fn = []() { emulator_state->reset(); };
}

Application::~Application() {
  // Free it
  if (emulator_state) {
    delete emulator_state;
  }
}

void Application::Render() {
  console.Draw("Console");
  disassembler.Draw();
  mem_edit.DrawWindow("Memory", emulator_state->memory.data(), MEMORY_SIZE);

  // Assembly Editor
  assembly_editor.Draw();
  // ImGui::Begin("Assembly Editor");
  // ImGui::InputTextMultiline("##asm_editor", assembly_code,
  //                           sizeof(assembly_code),
  //                           ImVec2(-FLT_MIN, ImGui::GetTextLineHeight() * 20));
  // if (ImGui::Button("Compile")) {
  //   emulator_state->assemble(assembly_code);
  // }
  // ImGui::End();

  // Stack Viewer
  ImGui::Begin("Stack Viewer");
  for (int i = 0; i < emulator_state->stack.size(); i++) {
    ImGui::Text("0x%lX: 0x%X", emulator_state->stack[i].first,
                emulator_state->stack[i].second);
    ImGui::Separator();
  }
  ImGui::End();

  // Register Viewer (ToDo: Include 8 bits registers)
  ImGui::Begin("Register Viewer");
  // Create a table with 2 columns: Register Name & Value
  ImGui::BeginTable("Registers", 2,
                    ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg);

  // Table headers
  ImGui::TableSetupColumn("Register", ImGuiTableColumnFlags_WidthFixed, 100.0f);
  ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthFixed, 120.0f);
  ImGui::TableHeadersRow();

  for (int i = 0; i < 9; i++) {
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::Text("%s", reg_names[i]); // Register name

    ImGui::TableSetColumnIndex(1);
    ImGui::Text("0x%08X", emulator_state->registers[i]);
  }

  ImGui::EndTable();
  ImGui::End();
}
