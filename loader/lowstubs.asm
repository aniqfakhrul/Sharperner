.code

EXTERN SW3_GetSyscallNumber: PROC

NtAccessCheck PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0FCD86AFAh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAccessCheck ENDP

NtWorkerFactoryWorkerReady PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 00AAA240Eh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtWorkerFactoryWorkerReady ENDP

NtAcceptConnectPort PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 036B11D6Eh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAcceptConnectPort ENDP

NtMapUserPhysicalPagesScatter PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0099E0707h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtMapUserPhysicalPagesScatter ENDP

NtWaitForSingleObject PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0B6258E89h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtWaitForSingleObject ENDP

NtCallbackReturn PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0F4BE34E8h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCallbackReturn ENDP

NtReadFile PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0283814AAh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtReadFile ENDP

NtDeviceIoControlFile PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 00C349806h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtDeviceIoControlFile ENDP

NtWriteFile PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0E9583C6Fh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtWriteFile ENDP

NtRemoveIoCompletion PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0440C6ADDh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtRemoveIoCompletion ENDP

NtReleaseSemaphore PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0FCB62A0Bh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtReleaseSemaphore ENDP

NtReplyWaitReceivePort PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 070F0417Ch        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtReplyWaitReceivePort ENDP

NtReplyPort PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0A43AC1A2h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtReplyPort ENDP

NtSetInformationThread PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 01A48DD6Bh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetInformationThread ENDP

NtSetEvent PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0CE8A340Ch        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetEvent ENDP

NtClose PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0F96CC830h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtClose ENDP

NtQueryObject PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0FED0944Eh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryObject ENDP

NtQueryInformationFile PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 02138A11Dh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryInformationFile ENDP

NtOpenKey PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 020204831h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtOpenKey ENDP

NtEnumerateValueKey PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 09990840Ah        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtEnumerateValueKey ENDP

NtFindAtom PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 00CDB6D4Ah        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtFindAtom ENDP

NtQueryDefaultLocale PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 089278E45h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryDefaultLocale ENDP

NtQueryKey PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 00E092992h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryKey ENDP

NtQueryValueKey PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 01F9F0E04h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryValueKey ENDP

NtAllocateVirtualMemory PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 00B970317h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAllocateVirtualMemory ENDP

NtQueryInformationProcess PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0653564A0h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryInformationProcess ENDP

NtWaitForMultipleObjects32 PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 00F9A084Fh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtWaitForMultipleObjects32 ENDP

NtWriteFileGather PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 094C8947Bh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtWriteFileGather ENDP

NtCreateKey PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 075CD6052h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateKey ENDP

NtFreeVirtualMemory PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 037B1110Fh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtFreeVirtualMemory ENDP

NtImpersonateClientOfPort PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 05CEF7976h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtImpersonateClientOfPort ENDP

NtReleaseMutant PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0FABADB17h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtReleaseMutant ENDP

NtQueryInformationToken PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 07DCB0724h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryInformationToken ENDP

NtRequestWaitReplyPort PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 002B41AD8h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtRequestWaitReplyPort ENDP

NtQueryVirtualMemory PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 003910F05h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryVirtualMemory ENDP

NtOpenThreadToken PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0ECB8E026h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtOpenThreadToken ENDP

NtQueryInformationThread PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 00EB65A09h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryInformationThread ENDP

NtOpenProcess PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0EDA60CCBh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtOpenProcess ENDP

NtSetInformationFile PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0AB3F532Bh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetInformationFile ENDP

NtMapViewOfSection PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0784E00A5h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtMapViewOfSection ENDP

NtAccessCheckAndAuditAlarm PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 066B94AE0h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAccessCheckAndAuditAlarm ENDP

NtUnmapViewOfSection PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0FAA61C36h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtUnmapViewOfSection ENDP

NtReplyWaitReceivePortEx PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0238DE7F1h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtReplyWaitReceivePortEx ENDP

NtTerminateProcess PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0763A9EA7h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtTerminateProcess ENDP

NtSetEventBoostPriority PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0268C3612h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetEventBoostPriority ENDP

NtReadFileScatter PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0238C2D1Dh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtReadFileScatter ENDP

NtOpenThreadTokenEx PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0069FC3C1h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtOpenThreadTokenEx ENDP

NtOpenProcessTokenEx PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 08486D258h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtOpenProcessTokenEx ENDP

NtQueryPerformanceCounter PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0E7CE015Ah        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryPerformanceCounter ENDP

NtEnumerateKey PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 069FF7444h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtEnumerateKey ENDP

NtOpenFile PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0B41AF8BCh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtOpenFile ENDP

NtDelayExecution PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 00DA9E5FFh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtDelayExecution ENDP

NtQueryDirectoryFile PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 094B38408h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryDirectoryFile ENDP

NtQuerySystemInformation PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0FA6C1BFFh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQuerySystemInformation ENDP

NtOpenSection PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 09748F79Ah        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtOpenSection ENDP

NtQueryTimer PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 013C22B68h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryTimer ENDP

NtFsControlFile PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 07838709Ah        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtFsControlFile ENDP

NtWriteVirtualMemory PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 03DD7097Bh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtWriteVirtualMemory ENDP

NtCloseObjectAuditAlarm PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 05A9FDB82h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCloseObjectAuditAlarm ENDP

NtDuplicateObject PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 006B86015h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtDuplicateObject ENDP

NtQueryAttributesFile PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0A682C01Ah        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryAttributesFile ENDP

NtClearEvent PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0F6ACC91Eh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtClearEvent ENDP

NtReadVirtualMemory PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 00D9F071Dh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtReadVirtualMemory ENDP

NtOpenEvent PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 000830D1Ah        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtOpenEvent ENDP

NtAdjustPrivilegesToken PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 06DC3215Eh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAdjustPrivilegesToken ENDP

NtDuplicateToken PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 015910510h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtDuplicateToken ENDP

NtContinue PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0CE183558h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtContinue ENDP

NtQueryDefaultUILanguage PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 09B35DB0Eh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryDefaultUILanguage ENDP

NtQueueApcThread PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0B898E226h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueueApcThread ENDP

NtYieldExecution PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 000946219h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtYieldExecution ENDP

NtAddAtom PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 054C15550h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAddAtom ENDP

NtCreateEvent PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0488B4B1Ch        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateEvent ENDP

NtQueryVolumeInformationFile PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0D940AB55h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryVolumeInformationFile ENDP

NtCreateSection PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 070EF123Fh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateSection ENDP

NtFlushBuffersFile PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 03EB55626h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtFlushBuffersFile ENDP

NtApphelpCacheControl PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0F9AFFB39h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtApphelpCacheControl ENDP

NtCreateProcessEx PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0048DC736h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateProcessEx ENDP

NtCreateThread PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 054D69CF9h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateThread ENDP

NtIsProcessInJob PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 09DF79199h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtIsProcessInJob ENDP

NtProtectVirtualMemory PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 00D810773h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtProtectVirtualMemory ENDP

NtQuerySection PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0CA86CCEEh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQuerySection ENDP

NtResumeThread PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 084D15667h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtResumeThread ENDP

NtTerminateThread PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 01822970Ah        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtTerminateThread ENDP

NtReadRequestData PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0CC4CE4DAh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtReadRequestData ENDP

NtCreateFile PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0DF79B47Fh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateFile ENDP

NtQueryEvent PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 072E40308h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryEvent ENDP

NtWriteRequestData PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 03898080Eh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtWriteRequestData ENDP

NtOpenDirectoryObject PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 01C2076BEh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtOpenDirectoryObject ENDP

NtAccessCheckByTypeAndAuditAlarm PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 04AD5AE42h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAccessCheckByTypeAndAuditAlarm ENDP

NtWaitForMultipleObjects PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0C19CC806h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtWaitForMultipleObjects ENDP

NtSetInformationObject PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0C29CCE23h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetInformationObject ENDP

NtCancelIoFile PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 02865E4CEh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCancelIoFile ENDP

NtTraceEvent PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 03091173Ah        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtTraceEvent ENDP

NtPowerInformation PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 003531BB9h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtPowerInformation ENDP

NtSetValueKey PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 06BAD0A76h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetValueKey ENDP

NtCancelTimer PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 00795E186h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCancelTimer ENDP

NtSetTimer PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0DF44D1D8h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetTimer ENDP

NtAccessCheckByType PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0ED649B89h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAccessCheckByType ENDP

NtAccessCheckByTypeResultList PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0B008AC87h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAccessCheckByTypeResultList ENDP

NtAccessCheckByTypeResultListAndAuditAlarm PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 038B6DF26h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAccessCheckByTypeResultListAndAuditAlarm ENDP

NtAccessCheckByTypeResultListAndAuditAlarmByHandle PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 08BD75362h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAccessCheckByTypeResultListAndAuditAlarmByHandle ENDP

NtAcquireProcessActivityReference PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 064D36D42h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAcquireProcessActivityReference ENDP

NtAddAtomEx PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 089913695h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAddAtomEx ENDP

NtAddBootEntry PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 08D90E170h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAddBootEntry ENDP

NtAddDriverEntry PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 01B963732h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAddDriverEntry ENDP

NtAdjustGroupsToken PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 004A0F3A2h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAdjustGroupsToken ENDP

NtAdjustTokenClaimsAndDeviceGroups PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 03A6C16B3h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAdjustTokenClaimsAndDeviceGroups ENDP

NtAlertResumeThread PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 07CDA7A43h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAlertResumeThread ENDP

NtAlertThread PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 08AA1511Eh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAlertThread ENDP

NtAlertThreadByThreadId PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0F9201E63h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAlertThreadByThreadId ENDP

NtAllocateLocallyUniqueId PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 00DAC9590h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAllocateLocallyUniqueId ENDP

NtAllocateReserveObject PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 028987A35h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAllocateReserveObject ENDP

NtAllocateUserPhysicalPages PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0833FECA4h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAllocateUserPhysicalPages ENDP

NtAllocateUuids PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0F5D104BCh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAllocateUuids ENDP

NtAllocateVirtualMemoryEx PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 08287D05Dh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAllocateVirtualMemoryEx ENDP

NtAlpcAcceptConnectPort PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 024B22520h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAlpcAcceptConnectPort ENDP

NtAlpcCancelMessage PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0F25ECD8Ch        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAlpcCancelMessage ENDP

NtAlpcConnectPort PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0E47EE5F0h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAlpcConnectPort ENDP

NtAlpcConnectPortEx PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0018ECCDBh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAlpcConnectPortEx ENDP

NtAlpcCreatePort PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0ED77D0DFh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAlpcCreatePort ENDP

NtAlpcCreatePortSection PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 00E942A07h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAlpcCreatePortSection ENDP

NtAlpcCreateResourceReserve PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0B4A2862Bh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAlpcCreateResourceReserve ENDP

NtAlpcCreateSectionView PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 00D2832A3h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAlpcCreateSectionView ENDP

NtAlpcCreateSecurityContext PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 01EA30B22h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAlpcCreateSecurityContext ENDP

NtAlpcDeletePortSection PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 08F278C4Ah        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAlpcDeletePortSection ENDP

NtAlpcDeleteResourceReserve PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 030A14C7Bh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAlpcDeleteResourceReserve ENDP

NtAlpcDeleteSectionView PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0B6ABA531h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAlpcDeleteSectionView ENDP

NtAlpcDeleteSecurityContext PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0EE35F3B4h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAlpcDeleteSecurityContext ENDP

NtAlpcDisconnectPort PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 000B71B38h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAlpcDisconnectPort ENDP

NtAlpcImpersonateClientContainerOfPort PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 02EBFA8A4h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAlpcImpersonateClientContainerOfPort ENDP

NtAlpcImpersonateClientOfPort PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 020B22920h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAlpcImpersonateClientOfPort ENDP

NtAlpcOpenSenderProcess PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 081A8E03Ch        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAlpcOpenSenderProcess ENDP

NtAlpcOpenSenderThread PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 02689E8A3h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAlpcOpenSenderThread ENDP

NtAlpcQueryInformation PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 00A84EF97h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAlpcQueryInformation ENDP

NtAlpcQueryInformationMessage PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0C255C3CBh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAlpcQueryInformationMessage ENDP

NtAlpcRevokeSecurityContext PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0D733D343h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAlpcRevokeSecurityContext ENDP

NtAlpcSendWaitReceivePort PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 024B73F38h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAlpcSendWaitReceivePort ENDP

NtAlpcSetInformation PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 00E1E0C8Bh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAlpcSetInformation ENDP

NtAreMappedFilesTheSame PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 019358032h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAreMappedFilesTheSame ENDP

NtAssignProcessToJobObject PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 098B5F049h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAssignProcessToJobObject ENDP

NtAssociateWaitCompletionPacket PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0296D03F2h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAssociateWaitCompletionPacket ENDP

NtCallEnclave PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 08EA9D00Ch        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCallEnclave ENDP

NtCancelIoFileEx PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 088AACB91h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCancelIoFileEx ENDP

NtCancelSynchronousIoFile PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 02993FB2Ah        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCancelSynchronousIoFile ENDP

NtCancelTimer2 PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 081920643h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCancelTimer2 ENDP

NtCancelWaitCompletionPacket PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0391D1F8Eh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCancelWaitCompletionPacket ENDP

NtCommitComplete PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0403CAC72h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCommitComplete ENDP

NtCommitEnlistment PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 079B70445h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCommitEnlistment ENDP

NtCommitRegistryTransaction PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0CF51CA3Ah        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCommitRegistryTransaction ENDP

NtCommitTransaction PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0D04BF2D7h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCommitTransaction ENDP

NtCompactKeys PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0BB04AE66h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCompactKeys ENDP

NtCompareObjects PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 061AC4971h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCompareObjects ENDP

NtCompareSigningLevels PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 010AA4E68h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCompareSigningLevels ENDP

NtCompareTokens PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0C507DB8Bh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCompareTokens ENDP

NtCompleteConnectPort PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0A4F1469Fh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCompleteConnectPort ENDP

NtCompressKey PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0FFD99A25h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCompressKey ENDP

NtConnectPort PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0E677F9D4h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtConnectPort ENDP

NtConvertBetweenAuxiliaryCounterAndPerformanceCounter PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0F74A15D6h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtConvertBetweenAuxiliaryCounterAndPerformanceCounter ENDP

NtCreateDebugObject PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0133663C9h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateDebugObject ENDP

NtCreateDirectoryObject PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0EAB3FE28h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateDirectoryObject ENDP

NtCreateDirectoryObjectEx PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0EA9ACE27h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateDirectoryObjectEx ENDP

NtCreateEnclave PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 03E5E1E94h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateEnclave ENDP

NtCreateEnlistment PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 07BE21875h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateEnlistment ENDP

NtCreateEventPair PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0A0B1A027h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateEventPair ENDP

NtCreateIRTimer PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 012086880h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateIRTimer ENDP

NtCreateIoCompletion PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0029423C7h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateIoCompletion ENDP

NtCreateJobObject PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0BA9749E8h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateJobObject ENDP

NtCreateJobSet PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0031E3851h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateJobSet ENDP

NtCreateKeyTransacted PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0961CE680h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateKeyTransacted ENDP

NtCreateKeyedEvent PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 00EA70722h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateKeyedEvent ENDP

NtCreateLowBoxToken PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0AF99FF3Ah        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateLowBoxToken ENDP

NtCreateMailslotFile PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0D97ADFD9h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateMailslotFile ENDP

NtCreateMutant PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0371206B6h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateMutant ENDP

NtCreateNamedPipeFile PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 018385EE4h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateNamedPipeFile ENDP

NtCreatePagingFile PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 036BCAE8Eh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreatePagingFile ENDP

NtCreatePartition PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0F6AFD4FFh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreatePartition ENDP

NtCreatePort PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 024BE392Eh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreatePort ENDP

NtCreatePrivateNamespace PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 006A61C1Bh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreatePrivateNamespace ENDP

NtCreateProcess PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0602360AEh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateProcess ENDP

NtCreateProfile PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 081264B01h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateProfile ENDP

NtCreateProfileEx PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0F4270652h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateProfileEx ENDP

NtCreateRegistryTransaction PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0DC57F20Fh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateRegistryTransaction ENDP

NtCreateResourceManager PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0B58DCB01h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateResourceManager ENDP

NtCreateSemaphore PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 01C4FC47Ah        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateSemaphore ENDP

NtCreateSymbolicLinkObject PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 018B87265h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateSymbolicLinkObject ENDP

NtCreateThreadEx PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0F22EACF8h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateThreadEx ENDP

NtCreateTimer PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 08CBAA622h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateTimer ENDP

NtCreateTimer2 PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0AE3622E8h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateTimer2 ENDP

NtCreateToken PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 067A05322h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateToken ENDP

NtCreateTokenEx PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0BA8D4807h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateTokenEx ENDP

NtCreateTransaction PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 034AE167Fh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateTransaction ENDP

NtCreateTransactionManager PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 015B74176h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateTransactionManager ENDP

NtCreateUserProcess PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0472A42A2h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateUserProcess ENDP

NtCreateWaitCompletionPacket PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0AD3987A6h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateWaitCompletionPacket ENDP

NtCreateWaitablePort PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 024A86372h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateWaitablePort ENDP

NtCreateWnfStateName PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0B3D08006h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateWnfStateName ENDP

NtCreateWorkerFactory PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 007144DC6h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateWorkerFactory ENDP

NtDebugActiveProcess PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 033993006h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtDebugActiveProcess ENDP

NtDebugContinue PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0C742A68Dh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtDebugContinue ENDP

NtDeleteAtom PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0BE339878h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtDeleteAtom ENDP

NtDeleteBootEntry PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 08990789Fh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtDeleteBootEntry ENDP

NtDeleteDriverEntry PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 02D811932h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtDeleteDriverEntry ENDP

NtDeleteFile PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0AE049494h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtDeleteFile ENDP

NtDeleteKey PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 027230A84h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtDeleteKey ENDP

NtDeleteObjectAuditAlarm PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 02CAD2034h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtDeleteObjectAuditAlarm ENDP

NtDeletePrivateNamespace PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 08DB2DA00h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtDeletePrivateNamespace ENDP

NtDeleteValueKey PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0FE3BFCA0h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtDeleteValueKey ENDP

NtDeleteWnfStateData PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 08699F088h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtDeleteWnfStateData ENDP

NtDeleteWnfStateName PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0B8B3CBA5h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtDeleteWnfStateName ENDP

NtDisableLastKnownGood PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0A1BD55BAh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtDisableLastKnownGood ENDP

NtDisplayString PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0DA462F14h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtDisplayString ENDP

NtDrawText PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0F44E925Ch        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtDrawText ENDP

NtEnableLastKnownGood PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 09836D6E7h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtEnableLastKnownGood ENDP

NtEnumerateBootEntries PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 08CA09B24h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtEnumerateBootEntries ENDP

NtEnumerateDriverEntries PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 004D3550Fh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtEnumerateDriverEntries ENDP

NtEnumerateSystemEnvironmentValuesEx PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 065CAB196h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtEnumerateSystemEnvironmentValuesEx ENDP

NtEnumerateTransactionObject PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 093B07BF3h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtEnumerateTransactionObject ENDP

NtExtendSection PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0C512D990h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtExtendSection ENDP

NtFilterBootOption PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0029A0E0Bh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtFilterBootOption ENDP

NtFilterToken PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 00F950D0Eh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtFilterToken ENDP

NtFilterTokenEx PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 00285403Eh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtFilterTokenEx ENDP

NtFlushBuffersFileEx PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 06892B6C4h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtFlushBuffersFileEx ENDP

NtFlushInstallUILanguage PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 017895632h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtFlushInstallUILanguage ENDP

NtFlushInstructionCache PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0055FD6E7h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtFlushInstructionCache ENDP

NtFlushKey PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 017D90E46h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtFlushKey ENDP

NtFlushProcessWriteBuffers PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0E1ABE73Fh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtFlushProcessWriteBuffers ENDP

NtFlushVirtualMemory PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0821FA2B6h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtFlushVirtualMemory ENDP

NtFlushWriteBuffer PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 00FB35D6Fh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtFlushWriteBuffer ENDP

NtFreeUserPhysicalPages PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0B566AAECh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtFreeUserPhysicalPages ENDP

NtFreezeRegistry PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 016831E15h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtFreezeRegistry ENDP

NtFreezeTransactions PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0915BE9ADh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtFreezeTransactions ENDP

NtGetCachedSigningLevel PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 03C9517CAh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtGetCachedSigningLevel ENDP

NtGetCompleteWnfStateSubscription PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 031AED73Eh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtGetCompleteWnfStateSubscription ENDP

NtGetContextThread PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 096AD5116h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtGetContextThread ENDP

NtGetCurrentProcessorNumber PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0B9928B2Eh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtGetCurrentProcessorNumber ENDP

NtGetCurrentProcessorNumberEx PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0B0BFE660h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtGetCurrentProcessorNumberEx ENDP

NtGetDevicePowerState PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 03E6010F0h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtGetDevicePowerState ENDP

NtGetMUIRegistryInfo PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 02CB503EBh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtGetMUIRegistryInfo ENDP

NtGetNextProcess PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 09E3CB661h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtGetNextProcess ENDP

NtGetNextThread PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0AA05E4AFh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtGetNextThread ENDP

NtGetNlsSectionPtr PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 03BD0138Eh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtGetNlsSectionPtr ENDP

NtGetNotificationResourceManager PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 091317B32h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtGetNotificationResourceManager ENDP

NtGetWriteWatch PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 098AA64AEh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtGetWriteWatch ENDP

NtImpersonateAnonymousToken PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 003930908h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtImpersonateAnonymousToken ENDP

NtImpersonateThread PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0B180E9BCh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtImpersonateThread ENDP

NtInitializeEnclave PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0235413D8h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtInitializeEnclave ENDP

NtInitializeNlsFiles PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 060DB9AB9h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtInitializeNlsFiles ENDP

NtInitializeRegistry PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0839CF96Fh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtInitializeRegistry ENDP

NtInitiatePowerAction PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0F06D143Fh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtInitiatePowerAction ENDP

NtIsSystemResumeAutomatic PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0296925C6h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtIsSystemResumeAutomatic ENDP

NtIsUILanguageComitted PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0824C40E2h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtIsUILanguageComitted ENDP

NtListenPort PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 05CFF3324h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtListenPort ENDP

NtLoadDriver PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 014DD700Ch        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtLoadDriver ENDP

NtLoadEnclaveData PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0B71F844Dh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtLoadEnclaveData ENDP

NtLoadHotPatch PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 01293660Ch        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtLoadHotPatch ENDP

NtLoadKey PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 02EBC4B51h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtLoadKey ENDP

NtLoadKey2 PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 07F928936h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtLoadKey2 ENDP

NtLoadKeyEx PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 06BECA7B8h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtLoadKeyEx ENDP

NtLockFile PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 024F84022h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtLockFile ENDP

NtLockProductActivationKeys PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0C43EDBD3h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtLockProductActivationKeys ENDP

NtLockRegistryKey PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0F449F7D2h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtLockRegistryKey ENDP

NtLockVirtualMemory PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0069B0E14h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtLockVirtualMemory ENDP

NtMakePermanentObject PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 01E83E68Fh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtMakePermanentObject ENDP

NtMakeTemporaryObject PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 00AD16A4Dh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtMakeTemporaryObject ENDP

NtManagePartition PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0376CF831h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtManagePartition ENDP

NtMapCMFModule PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0E1712925h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtMapCMFModule ENDP

NtMapUserPhysicalPages PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 039906ABCh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtMapUserPhysicalPages ENDP

NtMapViewOfSectionEx PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 038EA044Eh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtMapViewOfSectionEx ENDP

NtModifyBootEntry PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 03D9B1728h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtModifyBootEntry ENDP

NtModifyDriverEntry PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 04BD77366h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtModifyDriverEntry ENDP

NtNotifyChangeDirectoryFile PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0FDC43FE3h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtNotifyChangeDirectoryFile ENDP

NtNotifyChangeDirectoryFileEx PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0C424F29Bh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtNotifyChangeDirectoryFileEx ENDP

NtNotifyChangeKey PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 026223981h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtNotifyChangeKey ENDP

NtNotifyChangeMultipleKeys PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 02DB3341Eh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtNotifyChangeMultipleKeys ENDP

NtNotifyChangeSession PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 067F96B1Ah        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtNotifyChangeSession ENDP

NtOpenEnlistment PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 05986DE8Dh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtOpenEnlistment ENDP

NtOpenEventPair PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 010B42019h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtOpenEventPair ENDP

NtOpenIoCompletion PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 00ADE0C77h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtOpenIoCompletion ENDP

NtOpenJobObject PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 08EA1B6EDh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtOpenJobObject ENDP

NtOpenKeyEx PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0FA100D6Fh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtOpenKeyEx ENDP

NtOpenKeyTransacted PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 066FF6460h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtOpenKeyTransacted ENDP

NtOpenKeyTransactedEx PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0029EF0E4h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtOpenKeyTransactedEx ENDP

NtOpenKeyedEvent PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0088A1B0Ch        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtOpenKeyedEvent ENDP

NtOpenMutant PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 008B45312h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtOpenMutant ENDP

NtOpenObjectAuditAlarm PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 010365CE8h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtOpenObjectAuditAlarm ENDP

NtOpenPartition PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0F8623B32h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtOpenPartition ENDP

NtOpenPrivateNamespace PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0D642D9D1h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtOpenPrivateNamespace ENDP

NtOpenProcessToken PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0159D0118h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtOpenProcessToken ENDP

NtOpenRegistryTransaction PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 048915A1Dh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtOpenRegistryTransaction ENDP

NtOpenResourceManager PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0079F5F36h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtOpenResourceManager ENDP

NtOpenSemaphore PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 08A978A7Ah        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtOpenSemaphore ENDP

NtOpenSession PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0D20DD09Dh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtOpenSession ENDP

NtOpenSymbolicLinkObject PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 018B6664Bh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtOpenSymbolicLinkObject ENDP

NtOpenThread PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0A68EAA26h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtOpenThread ENDP

NtOpenTimer PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 00F8C7908h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtOpenTimer ENDP

NtOpenTransaction PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 01E47FF14h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtOpenTransaction ENDP

NtOpenTransactionManager PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0B1E59B79h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtOpenTransactionManager ENDP

NtPlugPlayControl PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 085D79A64h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtPlugPlayControl ENDP

NtPrePrepareComplete PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 03EB3A48Ch        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtPrePrepareComplete ENDP

NtPrePrepareEnlistment PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0D15AEEE9h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtPrePrepareEnlistment ENDP

NtPrepareComplete PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0492737E4h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtPrepareComplete ENDP

NtPrepareEnlistment PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0086729B1h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtPrepareEnlistment ENDP

NtPrivilegeCheck PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0801CF381h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtPrivilegeCheck ENDP

NtPrivilegeObjectAuditAlarm PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 06CD2703Ch        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtPrivilegeObjectAuditAlarm ENDP

NtPrivilegedServiceAuditAlarm PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0AA254ABAh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtPrivilegedServiceAuditAlarm ENDP

NtPropagationComplete PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 00B6FF922h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtPropagationComplete ENDP

NtPropagationFailed PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0B69666A2h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtPropagationFailed ENDP

NtPulseEvent PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 010AD230Ah        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtPulseEvent ENDP

NtQueryAuxiliaryCounterFrequency PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0069B3134h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryAuxiliaryCounterFrequency ENDP

NtQueryBootEntryOrder PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0914FCBE7h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryBootEntryOrder ENDP

NtQueryBootOptions PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 04B986107h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryBootOptions ENDP

NtQueryDebugFilterState PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 006552E16h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryDebugFilterState ENDP

NtQueryDirectoryFileEx PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 000BB4241h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryDirectoryFileEx ENDP

NtQueryDirectoryObject PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 02D3D27A3h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryDirectoryObject ENDP

NtQueryDriverEntryOrder PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 00B2E75C3h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryDriverEntryOrder ENDP

NtQueryEaFile PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0D8B8539Fh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryEaFile ENDP

NtQueryFullAttributesFile PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0603844FAh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryFullAttributesFile ENDP

NtQueryInformationAtom PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0DC40DFD0h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryInformationAtom ENDP

NtQueryInformationByName PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0663C6B96h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryInformationByName ENDP

NtQueryInformationEnlistment PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 07B4618D1h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryInformationEnlistment ENDP

NtQueryInformationJobObject PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 012B05C0Dh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryInformationJobObject ENDP

NtQueryInformationPort PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0A4BE50A1h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryInformationPort ENDP

NtQueryInformationResourceManager PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 03D191792h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryInformationResourceManager ENDP

NtQueryInformationTransaction PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 082C94079h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryInformationTransaction ENDP

NtQueryInformationTransactionManager PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0B130BFACh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryInformationTransactionManager ENDP

NtQueryInformationWorkerFactory PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 08F18978Bh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryInformationWorkerFactory ENDP

NtQueryInstallUILanguage PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0EFC9CE55h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryInstallUILanguage ENDP

NtQueryIntervalProfile PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0289EF7AAh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryIntervalProfile ENDP

NtQueryIoCompletion PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 00E946E43h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryIoCompletion ENDP

NtQueryLicenseValue PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0748E9504h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryLicenseValue ENDP

NtQueryMultipleValueKey PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0ADF08852h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryMultipleValueKey ENDP

NtQueryMutant PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0BA9CB51Fh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryMutant ENDP

NtQueryOpenSubKeys PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0A639ABA1h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryOpenSubKeys ENDP

NtQueryOpenSubKeysEx PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0159B4146h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryOpenSubKeysEx ENDP

NtQueryPortInformationProcess PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0462347ACh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryPortInformationProcess ENDP

NtQueryQuotaInformationFile PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0AC3B562Ch        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryQuotaInformationFile ENDP

NtQuerySecurityAttributesToken PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0DBE7C76Dh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQuerySecurityAttributesToken ENDP

NtQuerySecurityObject PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 02C12188Dh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQuerySecurityObject ENDP

NtQuerySecurityPolicy PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0AD9B92DBh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQuerySecurityPolicy ENDP

NtQuerySemaphore PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0140D4EACh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQuerySemaphore ENDP

NtQuerySymbolicLinkObject PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 01930F34Eh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQuerySymbolicLinkObject ENDP

NtQuerySystemEnvironmentValue PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0E4309BD4h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQuerySystemEnvironmentValue ENDP

NtQuerySystemEnvironmentValueEx PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0FFE4AB38h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQuerySystemEnvironmentValueEx ENDP

NtQuerySystemInformationEx PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 059932D6Eh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQuerySystemInformationEx ENDP

NtQueryTimerResolution PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0C69C844Fh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryTimerResolution ENDP

NtQueryWnfStateData PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0664EF971h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryWnfStateData ENDP

NtQueryWnfStateNameInformation PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 06AEA1629h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueryWnfStateNameInformation ENDP

NtQueueApcThreadEx PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 046BF8BF9h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQueueApcThreadEx ENDP

NtRaiseException PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0DCB6FC27h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtRaiseException ENDP

NtRaiseHardError PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 09F8FE57Ah        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtRaiseHardError ENDP

NtReadOnlyEnlistment PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0E3A6FE2Ch        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtReadOnlyEnlistment ENDP

NtRecoverEnlistment PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 019873831h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtRecoverEnlistment ENDP

NtRecoverResourceManager PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0633EB093h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtRecoverResourceManager ENDP

NtRecoverTransactionManager PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0B3A2E96Eh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtRecoverTransactionManager ENDP

NtRegisterProtocolAddressInformation PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0CA9BEC4Fh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtRegisterProtocolAddressInformation ENDP

NtRegisterThreadTerminatePort PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 067366EA2h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtRegisterThreadTerminatePort ENDP

NtReleaseKeyedEvent PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 018C1014Ch        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtReleaseKeyedEvent ENDP

NtReleaseWorkerFactoryWorker PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0EF53D798h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtReleaseWorkerFactoryWorker ENDP

NtRemoveIoCompletionEx PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 022D1ECA6h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtRemoveIoCompletionEx ENDP

NtRemoveProcessDebug PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 00A5A08F1h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtRemoveProcessDebug ENDP

NtRenameKey PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 09AF9BB60h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtRenameKey ENDP

NtRenameTransactionManager PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 005A56154h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtRenameTransactionManager ENDP

NtReplaceKey PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 09D98FC72h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtReplaceKey ENDP

NtReplacePartitionUnit PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 02889142Ah        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtReplacePartitionUnit ENDP

NtReplyWaitReplyPort PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0E8B1E529h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtReplyWaitReplyPort ENDP

NtRequestPort PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 05CB64334h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtRequestPort ENDP

NtResetEvent PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 03053D324h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtResetEvent ENDP

NtResetWriteWatch PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 02EA31236h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtResetWriteWatch ENDP

NtRestoreKey PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0DF1AE8A4h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtRestoreKey ENDP

NtResumeProcess PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0C024C7B1h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtResumeProcess ENDP

NtRevertContainerImpersonation PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 09647D89Bh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtRevertContainerImpersonation ENDP

NtRollbackComplete PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 01A575474h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtRollbackComplete ENDP

NtRollbackEnlistment PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 07BE28491h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtRollbackEnlistment ENDP

NtRollbackRegistryTransaction PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 00E922805h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtRollbackRegistryTransaction ENDP

NtRollbackTransaction PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 082CE4596h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtRollbackTransaction ENDP

NtRollforwardTransactionManager PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 00B9C5D38h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtRollforwardTransactionManager ENDP

NtSaveKey PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0EF4EC2EAh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSaveKey ENDP

NtSaveKeyEx PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0EBA4D91Eh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSaveKeyEx ENDP

NtSaveMergedKeys PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0BFD6A258h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSaveMergedKeys ENDP

NtSecureConnectPort PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 020B7071Ch        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSecureConnectPort ENDP

NtSerializeBoot PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 016C6684Dh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSerializeBoot ENDP

NtSetBootEntryOrder PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 03F90253Dh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetBootEntryOrder ENDP

NtSetBootOptions PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 047E9655Dh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetBootOptions ENDP

NtSetCachedSigningLevel PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0226934D2h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetCachedSigningLevel ENDP

NtSetCachedSigningLevel2 PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0F04B6FEAh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetCachedSigningLevel2 ENDP

NtSetContextThread PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0368E3A25h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetContextThread ENDP

NtSetDebugFilterState PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 062BC0470h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetDebugFilterState ENDP

NtSetDefaultHardErrorPort PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0E774E4EBh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetDefaultHardErrorPort ENDP

NtSetDefaultLocale PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 00120EE64h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetDefaultLocale ENDP

NtSetDefaultUILanguage PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 075AB7636h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetDefaultUILanguage ENDP

NtSetDriverEntryOrder PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0F3CDCB47h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetDriverEntryOrder ENDP

NtSetEaFile PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0C87AC7E8h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetEaFile ENDP

NtSetHighEventPair PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0133201ADh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetHighEventPair ENDP

NtSetHighWaitLowEventPair PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 03C8C4401h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetHighWaitLowEventPair ENDP

NtSetIRTimer PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0E03FE8A5h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetIRTimer ENDP

NtSetInformationDebugObject PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0BD17B9B8h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetInformationDebugObject ENDP

NtSetInformationEnlistment PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0C725A6F3h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetInformationEnlistment ENDP

NtSetInformationJobObject PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0388706CDh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetInformationJobObject ENDP

NtSetInformationKey PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 09694AD34h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetInformationKey ENDP

NtSetInformationResourceManager PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 08A1DBA9Fh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetInformationResourceManager ENDP

NtSetInformationSymbolicLink PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 036B81862h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetInformationSymbolicLink ENDP

NtSetInformationToken PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 08B140F0Eh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetInformationToken ENDP

NtSetInformationTransaction PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 04D416FD1h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetInformationTransaction ENDP

NtSetInformationTransactionManager PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 09A5D8EDBh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetInformationTransactionManager ENDP

NtSetInformationVirtualMemory PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 05DCA6171h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetInformationVirtualMemory ENDP

NtSetInformationWorkerFactory PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 09A1DB28Ah        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetInformationWorkerFactory ENDP

NtSetIntervalProfile PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0C496CC30h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetIntervalProfile ENDP

NtSetIoCompletion PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0128833DBh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetIoCompletion ENDP

NtSetIoCompletionEx PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0C153140Fh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetIoCompletionEx ENDP

NtSetLdtEntries PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 02692531Dh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetLdtEntries ENDP

NtSetLowEventPair PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 084324C6Fh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetLowEventPair ENDP

NtSetLowWaitHighEventPair PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 03490241Dh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetLowWaitHighEventPair ENDP

NtSetQuotaInformationFile PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0801FDEDCh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetQuotaInformationFile ENDP

NtSetSecurityObject PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 004BAECA5h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetSecurityObject ENDP

NtSetSystemEnvironmentValue PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0BAB92885h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetSystemEnvironmentValue ENDP

NtSetSystemEnvironmentValueEx PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0203D66C3h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetSystemEnvironmentValueEx ENDP

NtSetSystemInformation PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 004B3666Fh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetSystemInformation ENDP

NtSetSystemPowerState PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0C64D1C72h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetSystemPowerState ENDP

NtSetSystemTime PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 02FB7FE03h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetSystemTime ENDP

NtSetThreadExecutionState PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 092286242h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetThreadExecutionState ENDP

NtSetTimer2 PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0079BE70Dh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetTimer2 ENDP

NtSetTimerEx PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0069CB3A1h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetTimerEx ENDP

NtSetTimerResolution PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 01249D21Fh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetTimerResolution ENDP

NtSetUuidSeed PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0960BB495h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetUuidSeed ENDP

NtSetVolumeInformationFile PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 029B15D65h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetVolumeInformationFile ENDP

NtSetWnfProcessNotificationEvent PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0C848C9D2h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetWnfProcessNotificationEvent ENDP

NtShutdownSystem PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0AF6CA4F5h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtShutdownSystem ENDP

NtShutdownWorkerFactory PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 00C951878h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtShutdownWorkerFactory ENDP

NtSignalAndWaitForSingleObject PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 018352A8Ah        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSignalAndWaitForSingleObject ENDP

NtSinglePhaseReject PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 03684FED9h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSinglePhaseReject ENDP

NtStartProfile PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0E0BA926Dh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtStartProfile ENDP

NtStopProfile PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0F89DF12Bh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtStopProfile ENDP

NtSubscribeWnfStateChange PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0D444D5DEh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSubscribeWnfStateChange ENDP

NtSuspendProcess PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0612F9062h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSuspendProcess ENDP

NtSuspendThread PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0832F9394h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSuspendThread ENDP

NtSystemDebugControl PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 011813F1Bh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSystemDebugControl ENDP

NtTerminateEnclave PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 02EB13212h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtTerminateEnclave ENDP

NtTerminateJobObject PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 079514FEBh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtTerminateJobObject ENDP

NtTestAlert PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0E75AE4D5h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtTestAlert ENDP

NtThawRegistry PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0D64EDEC1h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtThawRegistry ENDP

NtThawTransactions PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 04B9F3577h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtThawTransactions ENDP

NtTraceControl PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 007904F43h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtTraceControl ENDP

NtTranslateFilePath PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 09F379B5Bh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtTranslateFilePath ENDP

NtUmsThreadYield PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0419D2F9Fh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtUmsThreadYield ENDP

NtUnloadDriver PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 03C952034h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtUnloadDriver ENDP

NtUnloadKey PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0081C2E43h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtUnloadKey ENDP

NtUnloadKey2 PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 04B1440CDh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtUnloadKey2 ENDP

NtUnloadKeyEx PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0B85FEA84h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtUnloadKeyEx ENDP

NtUnlockFile PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0D64724DEh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtUnlockFile ENDP

NtUnlockVirtualMemory PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 081DB4795h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtUnlockVirtualMemory ENDP

NtUnmapViewOfSectionEx PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 064911A17h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtUnmapViewOfSectionEx ENDP

NtUnsubscribeWnfStateChange PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 072A4E19Ch        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtUnsubscribeWnfStateChange ENDP

NtUpdateWnfStateData PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 08223B0B0h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtUpdateWnfStateData ENDP

NtVdmControl PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 005A9FFCFh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtVdmControl ENDP

NtWaitForAlertByThreadId PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0B7A90E93h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtWaitForAlertByThreadId ENDP

NtWaitForDebugEvent PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0E9B4341Dh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtWaitForDebugEvent ENDP

NtWaitForKeyedEvent PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0900B9780h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtWaitForKeyedEvent ENDP

NtWaitForWorkViaWorkerFactory PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 08942ADE1h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtWaitForWorkViaWorkerFactory ENDP

NtWaitHighEventPair PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0664A8120h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtWaitHighEventPair ENDP

NtWaitLowEventPair PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 016AE361Dh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtWaitLowEventPair ENDP

NtAcquireCMFViewOwnership PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 00D33D51Ah        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtAcquireCMFViewOwnership ENDP

NtCancelDeviceWakeupRequest PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0C50CD7E2h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCancelDeviceWakeupRequest ENDP

NtClearAllSavepointsTransaction PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 09DAB9939h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtClearAllSavepointsTransaction ENDP

NtClearSavepointTransaction PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0C843EAD7h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtClearSavepointTransaction ENDP

NtRollbackSavepointTransaction PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0C0EBE079h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtRollbackSavepointTransaction ENDP

NtSavepointTransaction PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0E209C29Bh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSavepointTransaction ENDP

NtSavepointComplete PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 058A3524Ch        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSavepointComplete ENDP

NtCreateSectionEx PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 084D1578Bh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateSectionEx ENDP

NtCreateCrossVmEvent PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 078A50D5Ch        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtCreateCrossVmEvent ENDP

NtGetPlugPlayEvent PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 060CCA59Ah        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtGetPlugPlayEvent ENDP

NtListTransactions PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 01A565C83h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtListTransactions ENDP

NtMarshallTransaction PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0800BE2C7h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtMarshallTransaction ENDP

NtPullTransaction PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0FE36FEA3h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtPullTransaction ENDP

NtReleaseCMFViewOwnership PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0168D2FC4h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtReleaseCMFViewOwnership ENDP

NtWaitForWnfNotifications PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 03DB7FDE4h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtWaitForWnfNotifications ENDP

NtStartTm PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 09F13FFEEh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtStartTm ENDP

NtSetInformationProcess PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0932D88A2h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtSetInformationProcess ENDP

NtRequestDeviceWakeup PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 065C27D4Ah        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtRequestDeviceWakeup ENDP

NtRequestWakeupLatency PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 06ABC4904h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtRequestWakeupLatency ENDP

NtQuerySystemTime PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 038F93D59h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtQuerySystemTime ENDP

NtManageHotPatch PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0ACA0AE3Bh        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtManageHotPatch ENDP

NtContinueEx PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 0C3408F84h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
NtContinueEx ENDP

RtlCreateUserThread PROC
        mov [rsp +8], rcx          ; Save registers.
        mov [rsp+16], rdx
        mov [rsp+24], r8
        mov [rsp+32], r9
        sub rsp, 28h
        mov ecx, 094A7CE19h        ; Load function hash into ECX.
        call SW3_GetSyscallNumber              ; Resolve function hash into syscall number.
        add rsp, 28h
        mov rcx, [rsp+8]                      ; Restore registers.
        mov rdx, [rsp+16]
        mov r8, [rsp+24]
        mov r9, [rsp+32]
        mov r10, rcx
        syscall                    ; Invoke system call.
        ret
RtlCreateUserThread ENDP

end