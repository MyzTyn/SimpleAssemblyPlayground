#include <unicorn/unicorn.h>
#include <keystone/keystone.h>
#include <iostream>
#include <vector>
#include <cstdio>

// Use nonzero base addresses for code and a high stack pointer.
#define CODE_ADDR 0x1000      // Code loaded at 0x1000
#define STACK_ADDR 0x2F00     // Safe high stack pointer value
#define MEM_SIZE 0x3000       // Map memory from 0x0000 to 0x3000

// Assembly source (for reference – we load our machine code directly)
// ToDo: Fix the Keystone Parser because recoginzed 12 as HEX not decimnal
const char* ASM_CODE = R"(
.globl _main
_main:
    # Print "Hello World"
    movl    $4, %eax            # Syscall number for sys_write
    movl    $1, %ebx            # File descriptor 1 (stdout)
    movl    $str, %ecx          # Pointer to string
    movl    $0xD, %edx           # Length of string
    int     $0x80               # Invoke syscall

    pushl   $2                  # Push second argument (value 2)
    pushl   $4                  # Push first argument (value 4)
    call    sum                 # Call sum; return address pushed
    
    # Print the result
    addl $0x30, %eax
    movb %al, result+8

    # Print "Result: X\n"
    movl    $4, %eax            # Syscall number for sys_write
    movl    $1, %ebx            # File descriptor 1 (stdout)
    movl    $result, %ecx       # Pointer to result string
    movl    $0xA, %edx           # Length of string
    int     $0x80               # Invoke syscall

    movl    %ebp, %esp          # Restore ESP (discard arguments)
    popl    %ebp                # Restore caller’s base pointer

    movl    $1, %eax            # Syscall number for exit
    xorl    %ebx, %ebx            # Exit code 0
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

// Syscall numbers (Linux IA-32)
#define SYS_EXIT 1
#define SYS_WRITE 4

// Hook to catch syscalls (unchanged)
void hook_syscall(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    uint32_t eax;
    uc_reg_read(uc, UC_X86_REG_EAX, &eax);  // Get syscall number

    if (eax == SYS_WRITE) {
        uint32_t fd, buf, len;
        uc_reg_read(uc, UC_X86_REG_EBX, &fd);
        uc_reg_read(uc, UC_X86_REG_ECX, &buf);
        uc_reg_read(uc, UC_X86_REG_EDX, &len);
        std::vector<char> data(len);
        uc_mem_read(uc, buf, data.data(), len);
//        printf("[DEBUG] SYS_WRITE fd: %u, buf: 0x%X, len: %u\n", fd, buf, len);
        std::cout << std::string(data.begin(), data.end());
    }
    else if (eax == SYS_EXIT) {
        uint32_t exit_code;
        uc_reg_read(uc, UC_X86_REG_EBX, &exit_code);
        std::cout << "[Emulator] sys_exit called. Exit code: " << exit_code << std::endl;
        uc_emu_stop(uc);
    }
    else {
        std::cout << "[Emulator] Unknown syscall: " << eax << std::endl;
    }
}

// Hook to inspect CPU state and dump the stack (reads from current ESP)
void hook_instr(uc_engine *uc, uint32_t id, uint64_t pc, void *user_data) {
    uint32_t eax, edx, ebx, esp, ebp;
    uint8_t stack_memory[0x14]; // Buffer for 20 bytes

    uc_reg_read(uc, UC_X86_REG_EAX, &eax);
    uc_reg_read(uc, UC_X86_REG_EDX, &edx);
    uc_reg_read(uc, UC_X86_REG_EBX, &ebx);
    uc_reg_read(uc, UC_X86_REG_ESP, &esp);
    uc_reg_read(uc, UC_X86_REG_EBP, &ebp);

    printf("EAX: 0x%X\n", eax);
    printf("EDX: 0x%X\n", edx);
    printf("EBX: 0x%X\n", ebx);
    printf("ESP: 0x%X\n", esp);
    printf("EBP: 0x%X\n", ebp);
    
    // Dump memory starting at current ESP
    if (uc_mem_read(uc, esp, stack_memory, sizeof(stack_memory)) == UC_ERR_OK) {
        printf("Stack memory dump (from ESP):\n");
        for (int i = 0; i < sizeof(stack_memory); i += 4) {
            printf("0x%X: %02X %02X %02X %02X\n", esp + i,
                   stack_memory[i], stack_memory[i+1],
                   stack_memory[i+2], stack_memory[i+3]);
        }
    } else {
        std::cerr << "Failed to read stack memory!" << std::endl;
    }
}

int main() {
    // Setup the Unicorn engine
    uc_engine *uc;
    // Setup the Keystone engine
    ks_engine *ks;

    // Initialize Unicorn engine for 32-bit x86
    if (uc_open(UC_ARCH_X86, UC_MODE_32, &uc) != UC_ERR_OK) {
        std::cerr << "Failed to initialize Unicorn engine!" << std::endl;
        return -1;
    }

    size_t count;
    unsigned char *encode;
    size_t size;

    // Initialize Keystone assembler for 32-bit x86 (ATT syntax)
    if (ks_open(KS_ARCH_X86, KS_MODE_32, &ks) != KS_ERR_OK) {
        std::cerr << "ERROR: failed on ks_open(), quit" << std::endl;
        return -1;
    }
    // Set the Syntax to AT&T style
    ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT);

    // (Optional) Assemble ASM_CODE if needed; here we use our machine code array.
    if (ks_asm(ks, ASM_CODE, CODE_ADDR, &encode, &size, &count) != KS_ERR_OK) {
        std::cerr << "ERROR: ks_asm() failed, error = " << ks_strerror(ks_errno(ks)) << std::endl;
        return -1;
    } else {
//        std::cout << "Generated machine code: ";
//        for (size_t i = 0; i < size; i++) {
//            std::cout << std::hex << (int)encode[i] << " ";
//        }
        std::cout << std::dec << "\nCompiled: " << size << " bytes, statements: " << count << std::endl;
    }
    

    // Map memory for code and stack
    if (uc_mem_map(uc, 0, MEM_SIZE, UC_PROT_ALL) != UC_ERR_OK) {
        std::cerr << "Failed to map memory!" << std::endl;
        return -1;
    }

    // Write machine code into memory at CODE_ADDR
    if (uc_mem_write(uc, CODE_ADDR, encode, size) != UC_ERR_OK) {
        std::cerr << "Failed to write code to memory!" << std::endl;
        return -1;
    }

    // Initialize registers
    uint32_t eax = 0;
    uint32_t ecx = 0;
    uint32_t esp = STACK_ADDR; // Set stack pointer to a safe high address
    uint32_t ebp = STACK_ADDR;
    uc_reg_write(uc, UC_X86_REG_EAX, &eax);
    uc_reg_write(uc, UC_X86_REG_ESP, &esp);
    uc_reg_write(uc, UC_X86_REG_EBP, &ebp);

    // Add hooks for instruction tracing and syscalls
    uc_hook trace, systemcall;
//    uc_hook_add(uc, &trace, UC_HOOK_CODE, (void*)hook_instr, NULL, CODE_ADDR, 0);
    uc_hook_add(uc, &systemcall, UC_HOOK_INTR, (void*)hook_syscall, NULL, CODE_ADDR, 0);

    // Start emulation from CODE_ADDR to the end of our code region
    uc_err err = uc_emu_start(uc, CODE_ADDR, CODE_ADDR + size, 0, 0);
    if (err != UC_ERR_OK) {
        std::cerr << "Emulation error: " << uc_strerror(err) << std::endl;
        return -1;
    }

    uc_reg_read(uc, UC_X86_REG_EAX, &eax);
    uc_reg_read(uc, UC_X86_REG_ECX, &ecx);
    std::cout << "[Emulator] EAX result: " << eax << std::endl;
    std::cout << "[Emulator] ECX result: " << ecx << std::endl;
    uint32_t esp_value, ebp_value;
    uc_reg_read(uc, UC_X86_REG_ESP, &esp_value);
    uc_reg_read(uc, UC_X86_REG_EBP, &ebp_value);
    std::cout << "[Emulator] ESP: 0x" << std::hex << esp_value << std::dec << std::endl;
    std::cout << "[Emulator] EBP: 0x" << std::hex << ebp_value << std::dec << std::endl;
    
    // Free the resources
    free(encode);
    ks_close(ks);
    uc_close(uc);
    
    return 0;
}
