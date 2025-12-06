OPTION CASEMAP:NONE

.code

Shellcode PROC
    push rbp
    push rbx
    push rcx
    push rsi
    push rdx
    push r10
    push r11
    push r12
    push r13
    push rdi
    mov rbp, rsp
    
    sub rsp, 40h
    and rsp, -10h


    mov rdi, qword ptr gs:[30h] ;TEB
    mov rdi, [rdi + 60h] ;PEB
    mov rdi, [rdi + 18h] ;Ldr
    mov rdi, [rdi + 10h] ;LDR_DATA
    ;_LDR_DATA_TABLE_ENTRY

FindKernel32:
    mov cx, word ptr [rdi+58h] ;UNICODE_STRING
    cmp cx, 24
    jne NextModule

    mov rsi, [rdi+58h+8h]

    mov bl, byte ptr [rsi+0*2h]
    cmp bl, "K"
    jne NextModule

    mov bl, byte ptr [rsi+6*2h]
    cmp bl, "3"
    jne NextModule

    mov bl, byte ptr [rsi+7*2h]
    cmp bl, "2"
    jne NextModule
      
    jmp FindSuccess
    

NextModule:
    mov rdi, [rdi]
    jmp FindKernel32
FindSuccess:
    mov r10, [rdi+30h]

    ; obtain LoadLibraryA and GetProcAddress
    movzx rdx, word ptr [r10+3Ch] ; e_lfnew
    add rdx, r10 ; NtHeader
    lea rdx, [rdx+4+20] ;OptionalHeader
    mov edx, dword ptr [rdx+70h] ;export offset
    
    add rdx, r10 ;Export
    mov rcx, -1
    mov ecx, dword ptr [rdx+18h] ;NumberOfNames
    mov r11d, dword ptr [rdx+1Ch] ;AddressOfFunction Offset
    mov r12d, dword ptr [rdx+20h] ;AddressOfNamnes Offset
    mov r13d, dword ptr [rdx+24h] ;AddressOFNameOrd Offset
    add r11, r10
    add r12, r10
    add r13, r10




    mov rsp, rbp
    pop rdi 
    pop r13
    pop r12
    pop r11
    pop r10
    pop rdx
    pop rsi
    pop rcx
    pop rbx
    pop rbp
    ret
Shellcode ENDP

END