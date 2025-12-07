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
    push r8     
    push r9
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
    mov ecx, dword ptr [rdx+18h] ;NumberOfNames
    mov r11d, dword ptr [rdx+1Ch] ;AddressOfFunction Offset
    mov r12d, dword ptr [rdx+20h] ;AddressOfNamnes Offset
    mov r13d, dword ptr [rdx+24h] ;AddressOFNameOrd Offset
    add r11, r10
    add r12, r10
    add r13, r10

    ; ==== Loadlib ====
    sub rsp, 60h

    mov byte ptr [rsp+0h], "L"
    mov byte ptr [rsp+1h], "o"
    mov byte ptr [rsp+2h], "a"
    mov byte ptr [rsp+3h], "d"
    mov byte ptr [rsp+4h], "L"
    mov byte ptr [rsp+5h], "i"
    mov byte ptr [rsp+6h], "b"
    mov byte ptr [rsp+7h], "r"
    mov byte ptr [rsp+8h], "a"
    mov byte ptr [rsp+9h], "r"
    mov byte ptr [rsp+0ah], "y"
    mov byte ptr [rsp+0bh], "A"
    mov byte ptr [rsp+0ch], 0
    mov byte ptr [rsp+0dh], "G"
    mov byte ptr [rsp+0eh], "e"
    mov byte ptr [rsp+0fh], "t"
    mov byte ptr [rsp+10h], "P"
    mov byte ptr [rsp+11h], "r"
    mov byte ptr [rsp+12h], "o"
    mov byte ptr [rsp+13h], "c"
    mov byte ptr [rsp+14h], "A"
    mov byte ptr [rsp+15h], "d"
    mov byte ptr [rsp+16h], "d"
    mov byte ptr [rsp+17h], "r"
    mov byte ptr [rsp+18h], "e"
    mov byte ptr [rsp+19h], "s"
    mov byte ptr [rsp+1ah], "s"
    mov byte ptr [rsp+1bh], 0

    mov qword ptr [rsp+20h], 0 ; bLoadRes
    mov qword ptr [rsp+28h], 0 ; bGetRes
    mov qword ptr [rsp+30h], rcx


    xor rbx, rbx
    
    ; while rbx <= rcx
StartFindTwo:
    cmp rbx, [rsp+30h]
    ja findLGLoop

StartFindLoadLibraryA:
    mov ecx, dword ptr [r12+rbx*4h]
    add rcx, r10
    lea rdx, [rsp+0h]
    call MyStrcmp
    cmp rax, 0
    jne StartFindGetProcAddress
findLoadSuccess:
    mov qword ptr [rsp+20h], 1
    mov qword ptr [rsp+38h], rbx ; Load idx in Export


StartFindGetProcAddress:
    mov ecx, dword ptr [r12+rbx*4h]
    add rcx, r10
    lea rdx, [rsp+0dh]
    call MyStrcmp
    cmp rax, 0
    jne CheckBothFound

findGetSuccess:
    mov qword ptr [rsp+28h], 1
    mov qword ptr [rsp+40h], rbx ; Get idx in Export

CheckBothFound:
    inc rbx
    cmp qword ptr [rsp+20h], 1
    jne StartFindTwo
    cmp qword ptr [rsp+28h], 1
    jne StartFindTwo

    

findLGLoop:
    cmp qword ptr [rsp+20h], 1
    jne ExitFindLoadAndGet
    mov rbx, qword ptr [rsp+38h]
    movzx rdi, word ptr [r13+rbx*2h]
    mov edi, dword ptr [r11+rdi*4h]
    add rdi, r10 
    mov r8, rdi ;LoadLibraryA
    cmp qword ptr [rsp+28h], 1
    jne ExitFindLoadAndGet
    mov rbx, qword ptr [rsp+40h]
    movzx rdi, word ptr [r13+rbx*2h]
    mov edi, dword ptr [r11+rdi*4h]
    add rdi, r10 
    mov r9, rdi ;GetProcAddress



ExitFindLoadAndGet:

    add rsp, 60h

     
    ; rax 现在存放 MessageBoxA 的地址


    mov rsp, rbp
    pop r9
    pop r8
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

MyStrcmp:
    push rbp
    push rsi
    push rdi
    push rcx
    push r8
    push r9
    mov rbp, rsp
    sub rsp, 28h
    and rsp, -10h
    mov rsi, rcx
    mov rdi, rdx
    xor rcx, rcx

    mov rax, 1h
    
strcmploop:
    mov r8b, byte ptr [rsi+rcx]
    mov r9b, byte ptr [rdi+rcx]
    cmp r8b, r9b
    jne bNoEqual
    cmp byte ptr [rsi+rcx], 0
    je bEqual
    inc rcx
    jmp strcmploop

bEqual:
    mov rax, 0h
bNoEqual:

    mov rsp, rbp
    pop r9
    pop r8
    pop rcx
    pop rdi
    pop rsi
    pop rbp

    ret
Shellcode ENDP

END