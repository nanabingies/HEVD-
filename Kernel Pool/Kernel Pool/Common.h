#pragma once
/*++

		  ##     ## ######## ##     ## ########
		  ##     ## ##       ##     ## ##     ##
		  ##     ## ##       ##     ## ##     ##
		  ######### ######   ##     ## ##     ##
		  ##     ## ##        ##   ##  ##     ##
		  ##     ## ##         ## ##   ##     ##
		  ##     ## ########    ###    ########

		HackSys Extreme Vulnerable Driver Exploit

Author : Ashfaq Ansari
Contact: ashfaq[at]payatu[dot]com
Website: http://www.payatu.com/

Copyright (C) 2011-2016 Payatu Technologies Pvt. Ltd. All rights reserved.

This program is free software: you can redistribute it and/or modify it under the terms of
the GNU General Public License as published by the Free Software Foundation, either version
3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program.
If not, see <http://www.gnu.org/licenses/>.

THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

See the file 'LICENSE' for complete copying permission.

Module Name:
	Common.h

Abstract:
	This module implements the data structures which is
	common to all the exploit modules.

--*/

#ifndef __COMMON_H__
#define __COMMON_H__

#pragma once

#include <time.h>
#include <stdio.h>
#include <Windows.h>
#include <Psapi.h>
#include <winioctl.h>
#include <TlHelp32.h>

#include "Payload.h"

#define BUFFER_SIZE 512
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#define DEVICE_NAME "\\\\.\\HackSysExtremeVulnerableDriver"
#define RandomNumber(Minimum, Maximum) (rand()%(int)(Maximum - Minimum) + Minimum)

#define OBJ_CASE_INSENSITIVE   0x00000040
#define DIRECTORY_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0xF)
#define SYMBOLIC_LINK_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0x1)

#define InitializeObjectAttributes(i, o, a, r, s) {  \
                (i)->Length = sizeof(OBJECT_ATTRIBUTES); \
                (i)->RootDirectory = r;                  \
                (i)->Attributes = a;                     \
                (i)->ObjectName = o;                     \
                (i)->SecurityDescriptor = s;             \
                (i)->SecurityQualityOfService = NULL;    \
            }

#define DEBUG_INFO(fmt, ...) do { ColoredConsoleOuput(FOREGROUND_BLUE, fmt, ##__VA_ARGS__); } while (0)
#define DEBUG_ERROR(fmt, ...) do { ColoredConsoleOuput(FOREGROUND_RED, fmt, ##__VA_ARGS__); } while (0)
#define DEBUG_SUCCESS(fmt, ...) do { ColoredConsoleOuput(FOREGROUND_GREEN, fmt, ##__VA_ARGS__); } while (0)
#define DEBUG_MESSAGE(fmt, ...) do { ColoredConsoleOuput(FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_GREEN, fmt, ##__VA_ARGS__); } while (0)

#define HACKSYS_EVD_IOCTL_STACK_OVERFLOW                  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_STACK_OVERFLOW_GS               CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_ARBITRARY_OVERWRITE             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_POOL_OVERFLOW                   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_ALLOCATE_UAF_OBJECT             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_USE_UAF_OBJECT                  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_FREE_UAF_OBJECT                 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_ALLOCATE_FAKE_OBJECT            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_TYPE_CONFUSION                  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_INTEGER_OVERFLOW                CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_NULL_POINTER_DEREFERENCE        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80A, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_UNINITIALIZED_STACK_VARIABLE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80B, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_UNINITIALIZED_HEAP_VARIABLE     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80C, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_DOUBLE_FETCH                    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80D, METHOD_NEITHER, FILE_ANY_ACCESS)
#define HACKSYS_EVD_IOCTL_INSECURE_KERNEL_FILE_ACCESS     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80E, METHOD_NEITHER, FILE_ANY_ACCESS)

typedef time_t TIME;

typedef struct _CLIENT_ID {
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

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

typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation,
	ProcessQuotaLimits,
	ProcessIoCounters,
	ProcessVmCounters,
	ProcessTimes,
	ProcessBasePriority,
	ProcessRaisePriority,
	ProcessDebugPort,
	ProcessExceptionPort,
	ProcessAccessToken,
	ProcessLdtInformation,
	ProcessLdtSize,
	ProcessDefaultHardErrorMode,
	ProcessIoPortHandlers,
	ProcessPooledUsageAndLimits,
	ProcessWorkingSetWatch,
	ProcessUserModeIOPL,
	ProcessEnableAlignmentFaultFixup,
	ProcessPriorityClass,
	ProcessWx86Information,
	ProcessHandleCount,
	ProcessAffinityMask,
	ProcessPriorityBoost,
	ProcessDeviceMap,
	ProcessSessionInformation,
	ProcessForegroundInformation,
	ProcessWow64Information,
	ProcessImageFileName,
	ProcessLUIDDeviceMapsEnabled,
	ProcessBreakOnTermination,
	ProcessDebugObjectHandle,
	ProcessDebugFlags,
	ProcessHandleTracing,
	ProcessIoPriority,
	ProcessExecuteFlags,
	ProcessTlsInformation,
	ProcessCookie,
	ProcessImageInformation,
	ProcessCycleTime,
	ProcessPagePriority,
	ProcessInstrumentationCallback,
	ProcessThreadStackAllocation,
	ProcessWorkingSetWatchEx,
	ProcessImageFileNameWin32,
	ProcessImageFileMapping,
	ProcessAffinityUpdateMode,
	ProcessMemoryAllocationMode,
	ProcessGroupInformation,
	ProcessTokenVirtualizationEnabled,
	ProcessConsoleHostProcess,
	ProcessWindowInformation,
	MaxProcessInfoClass
} PROCESSINFOCLASS;

typedef struct _PROCESS_ACCESS_TOKEN {
	HANDLE Token;
	HANDLE Thread;
} PROCESS_ACCESS_TOKEN, * PPROCESS_ACCESS_TOKEN;

typedef struct _EPROCESS {
	UCHAR NotNeeded1[0x26C];
	union {
		ULONG Flags2;
		struct {
			ULONG JobNotReallyActive : 1;
			ULONG AccountingFolded : 1;
			ULONG NewProcessReported : 1;
			ULONG ExitProcessReported : 1;
			ULONG ReportCommitChanges : 1;
			ULONG LastReportMemory : 1;
			ULONG ReportPhysicalPageChanges : 1;
			ULONG HandleTableRundown : 1;
			ULONG NeedsHandleRundown : 1;
			ULONG RefTraceEnabled : 1;
			ULONG NumaAware : 1;
			ULONG ProtectedProcess : 1;
			ULONG DefaultPagePriority : 3;
			ULONG PrimaryTokenFrozen : 1;
			ULONG ProcessVerifierTarget : 1;
			ULONG StackRandomizationDisabled : 1;
			ULONG AffinityPermanent : 1;
			ULONG AffinityUpdateEnable : 1;
			ULONG PropagateNode : 1;
			ULONG ExplicitAffinity : 1;
		};
	};
	UCHAR NotNeeded2[0x50];
} EPROCESS, * PEPROCESS;

typedef struct _PROCESS_DEVICEMAP_INFORMATION {
	HANDLE DirectoryHandle;
} PROCESS_DEVICEMAP_INFORMATION, * PPROCESS_DEVICEMAP_INFORMATION;

typedef NTSTATUS(WINAPI* ZwClose_t)(IN HANDLE hObject);

typedef PEPROCESS(WINAPI* PsGetCurrentProcess_t)(VOID);

typedef PACCESS_TOKEN(WINAPI* PsReferencePrimaryToken_t)(IN OUT PVOID Process);

typedef NTSTATUS(WINAPI* NtQueryIntervalProfile_t)(IN ULONG   ProfileSource,
	OUT PULONG Interval);

typedef NTSTATUS(WINAPI* ZwOpenProcessToken_t)(IN HANDLE      ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	OUT PHANDLE    TokenHandle);

typedef NTSTATUS(WINAPI* PsLookupProcessByProcessId_t)(IN HANDLE ProcessId,
	OUT PVOID Process);

typedef NTSTATUS(WINAPI* ZwSetInformationProcess_t)(IN HANDLE ProcessHandle,
	IN ULONG  ProcessInformationClass,
	IN PVOID  ProcessInformation,
	IN ULONG  ProcessInformationLength);

typedef NTSTATUS(WINAPI* ZwOpenProcess_t)(OUT PHANDLE           ProcessHandle,
	IN ACCESS_MASK        DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID         ClientId OPTIONAL);

typedef NTSTATUS(WINAPI* NtAllocateVirtualMemory_t)(IN HANDLE     ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN ULONG      ZeroBits,
	IN OUT PULONG AllocationSize,
	IN ULONG      AllocationType,
	IN ULONG      Protect);

typedef NTSTATUS(WINAPI* NtAllocateReserveObject_t)(OUT PHANDLE           hObject,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN DWORD              ObjectType);

typedef NTSTATUS(WINAPI* NtMapUserPhysicalPages_t)(IN PVOID          VirtualAddress,
	IN ULONG_PTR      NumberOfPages,
	IN OUT PULONG_PTR UserPfnArray);

typedef NTSTATUS(WINAPI* ZwDuplicateToken_t)(IN HANDLE             ExistingTokenHandle,
	IN ACCESS_MASK        DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN BOOLEAN            EffectiveOnly,
	IN TOKEN_TYPE         TokenType,
	OUT PHANDLE           NewTokenHandle);

typedef NTSTATUS(WINAPI* NtQuerySystemInformation_t)(IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID                   SystemInformation,
	IN ULONG                    SystemInformationLength,
	OUT PULONG                  ReturnLength);


typedef NTSTATUS(WINAPI* NtSetInformationProcess_t)(IN HANDLE           ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	IN PVOID            ProcessInformation,
	IN ULONG            ProcessInformationLength);

typedef NTSTATUS(WINAPI* NtCreateDirectoryObject_t)(OUT PHANDLE           DirectoryHandle,
	IN ACCESS_MASK        DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

typedef NTSTATUS(WINAPI* NtOpenDirectoryObject_t)(OUT PHANDLE           DirectoryHandle,
	IN ACCESS_MASK        DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

typedef VOID(WINAPI* RtlInitUnicodeString_t)(IN OUT PUNICODE_STRING DestinationString,
	IN PCWSTR              SourceString OPTIONAL);

typedef NTSTATUS(WINAPI* NtCreateSymbolicLinkObject_t)(OUT PHANDLE           SymbolicLinkHandle,
	IN ACCESS_MASK        DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PUNICODE_STRING    TargetName);

ZwClose_t                     ZwClose;
ZwOpenProcess_t               ZwOpenProcess;
ZwDuplicateToken_t            ZwDuplicateToken;
ZwOpenProcessToken_t          ZwOpenProcessToken;
PsGetCurrentProcess_t         PsGetCurrentProcess;
RtlInitUnicodeString_t        RtlInitUnicodeString;
NtOpenDirectoryObject_t       NtOpenDirectoryObject;
NtMapUserPhysicalPages_t      NtMapUserPhysicalPages;
NtQueryIntervalProfile_t      NtQueryIntervalProfile;
NtSetInformationProcess_t     NtSetInformationProcess;
ZwSetInformationProcess_t     ZwSetInformationProcess;
NtAllocateReserveObject_t     NtAllocateReserveObject;
NtAllocateVirtualMemory_t     NtAllocateVirtualMemory;
NtCreateDirectoryObject_t     NtCreateDirectoryObject;
PsReferencePrimaryToken_t     PsReferencePrimaryToken;
NtQuerySystemInformation_t    NtQuerySystemInformation;
PsLookupProcessByProcessId_t  PsLookupProcessByProcessId;
NtCreateSymbolicLinkObject_t  NtCreateSymbolicLinkObject;

BOOL ExploitSuccessful;

BOOL      MapNullPage();
VOID      ClearScreen();
VOID      ResolveKernelAPIs();
VOID      CenterConsoleScreen();
PVOID     GetHalDispatchTable();
ULONG     GetNumberOfProcessors();
DWORD     GetProcessID(LPCSTR ProcessName);
HANDLE    GetDeviceHandle(LPCSTR FileName);
VOID      ColoredConsoleOuput(WORD wColor, CONST PTCHAR fmt, ...);

#endif //__COMMON_H__
