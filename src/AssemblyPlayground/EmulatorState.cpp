//
//  EmulatorState.c
//  ia32_emulator
//
//  Created by MyzTyn on 2025/04/07.
//

#include "EmulatorState.h"

#include "unicorn/unicorn.h"

int reg_ids[] = {
    UC_X86_REG_EAX,
    UC_X86_REG_EBX,
    UC_X86_REG_ECX,
    UC_X86_REG_EDX,
    UC_X86_REG_ESP,
    UC_X86_REG_EBP,
    UC_X86_REG_ESI,
    UC_X86_REG_EDI,
    UC_X86_REG_EIP
};

// Syscall numbers
#define SYS_EXIT 1
#define SYS_WRITE 4

//static void hook_mem_access(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
//    printf("[MEM ACCESS] %s at 0x%llx, value: 0x%llx\n",
//           (type == UC_MEM_WRITE) ? "WRITE" : "READ",
//           address, value);
//}

// Hook to catch syscalls (Simple Kernel)
void hook_syscall(uc_engine *uc, uint32_t intno, void *user_data) {
    EmulatorState* emulator_state = (EmulatorState*)user_data;
    emulator_state->update_registers();
    
    uint32_t eax = emulator_state->registers[0];  // Get syscall number (EAX register)
    
    if (eax == SYS_WRITE) {
        uint32_t fd = emulator_state->registers[1];  // EBX (file descriptor)
        uint32_t buf = emulator_state->registers[2]; // ECX (buffer address)
        uint32_t len = emulator_state->registers[3]; // EDX (length)
        //        printf("[DEBUG] SYS_WRITE fd: %u, buf: 0x%X, len: %u\n", fd, buf, len);
        
        // Directly reference emulator state memory
        char* data = reinterpret_cast<char*>(&emulator_state->memory[buf]);
        // Print the data safely with length limitation
        //        printf("%.*s", len, data);
        emulator_state->console->AddLog("%.*s", len, data);
    }
    else if (eax == SYS_EXIT) {
        uint32_t exit_code = emulator_state->registers[1]; // EBX (exit code)
        //        printf("[SYSCALL] sys_exit called. Exit code: %d\n", exit_code);
        emulator_state->console->AddLog("Program exited: %d", exit_code);
        uc_emu_stop(uc); // Stop the emulation
    }
    else {
        printf("[SYSCALL] Unknown syscall: %d\n", eax);
    }
}

EmulatorState::EmulatorState(): uc(nullptr), ks(nullptr), registers{}, registeres_ptrs{}, memory{}, ESP_Address(0x1500), EBP_Address(0x1500), StartAddress(0x200), END_ADDRESS(0) {
    // Initialize Unicorn engine
    if (uc_open(UC_ARCH_X86, UC_MODE_32, &uc) != UC_ERR_OK) {
        throw std::runtime_error("Failed to initialize Unicorn engine!");
    }
    // Initialize Keystone assembler for 32-bit x86 (ATT syntax)
    if (ks_open(KS_ARCH_X86, KS_MODE_32, &ks) != KS_ERR_OK) {
        throw std::runtime_error("Failed to initialize Keystone engine");
    }
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &capstone) != CS_ERR_OK) {
        throw std::runtime_error("Failed to initialize Capstone engine");
    }
    
    // Register the system call
    uc_hook syscall;
    uc_hook_add(uc, &syscall, UC_HOOK_INTR, (void*)hook_syscall, this, StartAddress, 0);
    
    // Set the Syntax to AT&T
    ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT);
    cs_option(capstone, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
    
    // Assign each element of ptrs to point to the corresponding reg_values element
    for (int i = 0; i < REG_TOTAL; i++) {
        registeres_ptrs[i] = &registers[i];  // Store addresses of each element
    }
    
    // Map the memory
    if (uc_mem_map_ptr(uc, 0, MEMSIZE, UC_PROT_ALL, memory.data()) != UC_ERR_OK) {
        throw std::runtime_error("Failed to map the memory");
    }
    
    stack.reserve(10);
    stack.clear();
}

EmulatorState::~EmulatorState() {
    uc_close(uc);
    ks_close(ks);
    cs_close(&capstone);
    console = NULL;
}

// run to the end
void EmulatorState::run() {
    reset();
    
    // Start the cpu
    uc_emu_start(uc, StartAddress, END_ADDRESS, 0, 0);
    update_registers();
    read_stack();
}

void EmulatorState::step() {
    // Start the cpu
    uc_emu_start(uc, registers[8], END_ADDRESS, 0, 1);
    update_registers();
    read_stack();
}

// clear the state
void EmulatorState::reset() {
    // Clear and setup the registers
    registers.fill(0);
    registers[4] = ESP_Address;
    registers[5] = EBP_Address;
    registers[8] = StartAddress;
    uc_reg_write_batch(uc, reg_ids, registeres_ptrs.data(), REG_TOTAL);
    // Update it
    update_pc_fn(StartAddress);
    read_stack();
}

// ToDo: DISPLAY IF ASM CODE ERROR
// Assmble the assembly code and load to the memory
void EmulatorState::assemble(const char* value) {
    size_t count, size;
    uint8_t *encode;
    
    // Compile the ASM code
    if (ks_asm(ks, value, StartAddress, &encode, &size, &count) == KS_ERR_OK) {
        console->AddLog("ASM code compiled! %zu bytes, statements: %zu", size, count);
    }
    
    END_ADDRESS = StartAddress + size;
    
    // Set the memory to 0
    memory.fill(0);
    // Copy compiled code to memory_data (single copy)
    std::copy_n(encode, size, memory.begin() + StartAddress);
    
    // For Capstone Engine
    cs_insn *insn;
    size_t count_t;
    
    disassemble(encode, size, &insn, &count_t);
    if (count_t > 0) {
        console->AddLog("ASM code disassembled! %zu instructions", count_t);
        // Set the data to Disassembler
        update_disassembler_fn(insn, count_t);
        reset();
        // Clear the cache to update the new code
        uc_ctl_remove_cache(uc, StartAddress, MEMSIZE);
    } else {
        console->AddLog("[error] Failed to disassemble given code!");
    }
    
    // Free encode data
    free(encode);
}

void EmulatorState::disassemble(uint8_t* machine_code, size_t size, cs_insn** insn, size_t* count) {
    *count = cs_disasm(capstone, machine_code, size, StartAddress, 0, insn);
    
    if (*count == 0) {
        *insn = NULL;  // Ensure insn is NULL if disassembly fails
    }
}

void EmulatorState::update_registers() {
    uc_reg_read_batch(uc, reg_ids, registeres_ptrs.data(), REG_TOTAL);
    update_pc_fn(registers[8]);
}

void EmulatorState::read_stack() {
    size_t size = ESP_Address - registers[4];
    stack.clear();
    
    if (size == 0) {
        return;
    }
    
    for (uint32_t addr = registers[4]; addr < EBP_Address; addr += 4) {
        uint32_t value = *reinterpret_cast<uint32_t*>(&memory[addr]);
        stack.emplace_back(addr, value);
    }
}
