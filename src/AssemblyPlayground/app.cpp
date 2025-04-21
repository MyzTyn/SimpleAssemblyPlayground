//
//  app.cpp
//  ia32_emulator
//
//  Created by MyzTyn on 2025/03/26.
//

#include "app.h"

#include <array>
#include <cinttypes>
#include <string>
#include <vector>

#include "imgui_memory_editor.h"
#include "capstone/capstone.h"
#include "keystone/keystone.h"
#include "unicorn/unicorn.h"
#include "imgui.h"

#include "AppUI.h"
#include "Console.h"
#include "EmulatorState.h"

// ToDo: Redo the code for safety
// ToDo: Clear global vars

static Disassembler disassembler;
static MemoryEditor mem_edit;

// Register names
const char *reg_names[] = {"EAX", "EBX", "ECX", "EDX", "ESP",
                           "EBP", "ESI", "EDI", "EIP"};

static EmulatorState *emulator_state;
static AssemblyCodeEditor* assembly_editor;

Application::Application() : io_(ImGui::GetIO()) {

  io_.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
  io_.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
  //    io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;

  ImGui::StyleColorsDark();
  ImGuiStyle &style = ImGui::GetStyle();
  if (io_.ConfigFlags & ImGuiConfigFlags_ViewportsEnable) {
    style.WindowRounding = 0.0f;
    style.Colors[ImGuiCol_WindowBg].w = 1.0f;
  }

  // Setup
  emulator_state = new EmulatorState();
  assembly_editor = new AssemblyCodeEditor();

  // Event callback (Remove those)
  emulator_state->update_pc_fn = [](uint32_t pc) {
    disassembler.current_pc = pc;
  };
  disassembler.run_fn = []() { emulator_state->run(); };
  disassembler.step_fn = []() { emulator_state->step(); };
  disassembler.reset_fn = []() { emulator_state->reset(); };

  assembly_editor->on_duplicate_check = [](const char* code) -> bool {
    if (!emulator_state->executable_data || strcmp(code, emulator_state->executable_data->code.c_str()) != 0) {
      return false;
    }

    return true;
  };

  assembly_editor->on_compiled = [](const ExecutableData *executable_data) {
    delete emulator_state->executable_data;
    emulator_state->executable_data = executable_data;

    disassembler.instructions = executable_data->instructions;
    disassembler.instruction_count = executable_data->instruction_size;

    // Set the memory to 0
    emulator_state->memory.fill(0);
    // Copy compiled code to memory_data (single copy)
    std::copy_n(executable_data->bin, executable_data->bin_size, emulator_state->memory.begin() +  executable_data->default_start_address);

    emulator_state->reset();
  };

  emulator_state->has_breakpoint = [](uint64_t address) -> bool {
    if (disassembler.breakpoints[address]) {
      disassembler.breakpoints[address] = false;
      return true;
    }
    return false;
  };
}

Application::~Application() {
  // Free it
  delete emulator_state;
}

void Application::Render() {
  Console::Instance().Draw("Console");
  disassembler.Draw();
  mem_edit.DrawWindow("Memory", emulator_state->memory.data(), MEMORY_SIZE);

  // Assembly Editor
  assembly_editor->Draw();

  // Stack Viewer
  ImGui::Begin("Stack Viewer");
  for (const auto & i : emulator_state->stack) {
    ImGui::Text("0x%" PRIX64 ": 0x%04" PRIX32, i.first,
                i.second);
    ImGui::Separator();
  }
  ImGui::End();

  // Register Viewer (ToDo: Include 8 bits registers)
  ImGui::Begin("Register Viewer");
  // Create a table with 2 columns: Register Name & Value
  ImGui::BeginTable("Registers", 2,
                    ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg);

  // Table headers
  ImGui::TableSetupColumn("Register", ImGuiTableColumnFlags_WidthFixed, 100.0F);
  ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthFixed, 120.0F);
  ImGui::TableHeadersRow();

  for (int i = 0; i < REGISTERS_TOTAL; i++) {
    ImGui::TableNextRow();
    ImGui::TableSetColumnIndex(0);
    ImGui::Text("%s", reg_names[i]); // Register name

    ImGui::TableSetColumnIndex(1);
    ImGui::Text("0x%08" PRIX32, emulator_state->registers[i]);
  }

  ImGui::EndTable();
  ImGui::End();
}
