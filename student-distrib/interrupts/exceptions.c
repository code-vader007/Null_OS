#include "exceptions.h"
#include "../devices/vga_text.h"


char *exceptions[20] = {
    "Division by 0",
    "Debug",
    "Non-maskable Interrupt",
    "Breakpoint",
    "Overflow",
    "Bound Range Exceeded",
    "Invalid Opcode",
    "Device Not Available",
    "Double Fault",
    "Coprocessor Segment Overrun",
    "Invalid TSS",
    "Segment Not Present",
    "Stack Segment Fault",
    "General Protection Fault",
    "Page Fault",
    "Reserved",
    "x87 Floating Point Exception",
    "Alignment Check",
    "Machine Check",
    "SIMD Floating Point Exception"
};

/* void exception_handler_real(char* message)
 * @input: message - reason of this exception
 * @output: - a picture of anime character Aqua, on bottom right of screen
 *          - a big 00P5
 *          - reason of this exception
 * @effects: - interrupts are disabled
 *           - system put into infinite loop
 * @description: the function to handle all the different exceptions.
 */
void exception_handler_real(uint32_t id, pushal_t pushal, uint32_t err_code, iret_t iret) {
    cli();  // Disable interruption

    // Print the big 00P5 and exception message
    /*
    printf("+---+ +---+ +---+ +---+\n");
    printf("|   | |   | |   | |    \n");
    printf("| . | | . | +---+ +---+\n");
    printf("|   | |   | |         |\n");
    printf("+---+ +---+ +     +---+\n");
    */
    printf("The following exception happened:\n- %s\n", exceptions[id]);

    printf("PushAL Info:\n");
    printf("- EAX=0x%x, EBX=0x%x, ECX=0x%x, EDX=0x%x\n", pushal.eax, pushal.ebx, pushal.ecx, pushal.edx);
    printf("- ESI=0x%x, EDI=0x%x, EBP=0x%x, ESP=0x%x\n", pushal.esi, pushal.edi, pushal.ebp, pushal.esp);
    printf("IRet Info:\n");
    printf("- EIP=0x%x, CS=0x%x, EFLAGS=0x%x, ESP=0x%x, SS=0x%x\n", iret.eip, iret.cs, iret.eflags, iret.esp, iret.ss);
    printf("Error Code: 0x%x\n", err_code);

    if(id == EXCEPTION_INVALID_TSS
        || id == EXCEPTION_SEGMENT_NOT_PRESENT
        || id == EXCEPTION_STACK_SEGMENT_FAULT
        || id == EXCEPTION_GENERAL_PROTECTION_FAULT) {
        // Visit https://wiki.osdev.org/Exceptions#Selector_Error_Code for details.
        printf("Exception Details:\n");
        printf("- Origin: %s\n", (err_code & 0x1) ? "External" : "Internal");
        printf("- Table: %s\n", (err_code & 0x4) ? (
            (err_code & 0x2) ? "IDT" : "LDT"
        ) : (
            (err_code & 0x2) ? "IDT" : "GDT"
        ));
        printf("- Selector Index: 0x%x\n", err_code >> 3);
    } else if(id == EXCEPTION_PAGE_FAULT) {
        // Visit https://wiki.osdev.org/Exceptions for details.
        uint32_t page_fault_pos;
        asm volatile("movl %%cr2, %0":"=r"(page_fault_pos));
        printf("Exception Details:\n");
        printf("- Reason: %s\n", (err_code & 0x1) ? "Page Protection Violation" : "Non-present Page");
        printf("- Operation: %s\n", (err_code & 0x2) ? "Write" : "Read");
        printf("- Privilege Violation: %s\n", (err_code & 0x04) ? "Yes" : "No");
        printf("- Reserved Write: %s\n", (err_code & 0x08) ? "Yes" : "No");
        printf("- Instruction Fetch: %s\n", (err_code & 0x10) ? "Yes" : "No");
        printf("- Target Virtual Addr: 0x%x\n", page_fault_pos);
    }

    
    sti();

    // Kill the current process
    syscall_halt(255);
}
