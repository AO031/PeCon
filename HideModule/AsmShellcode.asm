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
    
    sub rsp, 120h
    and rsp, -10h

    mov byte ptr [rsp+20h], "L"
    mov byte ptr [rsp+21h], "o"
    mov byte ptr [rsp+22h], "a"
    mov byte ptr [rsp+23h], "d"
    mov byte ptr [rsp+24h], "L"
    mov byte ptr [rsp+25h], "i"
    mov byte ptr [rsp+26h], "b"
    mov byte ptr [rsp+27h], "r"
    mov byte ptr [rsp+28h], "a"
    mov byte ptr [rsp+29h], "r"
    mov byte ptr [rsp+2Ah], "y"
    mov byte ptr [rsp+2Bh], "A"
    mov byte ptr [rsp+2Ch], 0

    mov byte ptr [rsp+2Dh], "G"
    mov byte ptr [rsp+2Eh], "e"
    mov byte ptr [rsp+2Fh], "t"
    mov byte ptr [rsp+30h], "P"
    mov byte ptr [rsp+31h], "r"
    mov byte ptr [rsp+32h], "o"
    mov byte ptr [rsp+33h], "c"
    mov byte ptr [rsp+34h], "A"
    mov byte ptr [rsp+35h], "d"
    mov byte ptr [rsp+36h], "d"
    mov byte ptr [rsp+37h], "r"
    mov byte ptr [rsp+38h], "e"
    mov byte ptr [rsp+39h], "s"
    mov byte ptr [rsp+3Ah], "s"
    mov byte ptr [rsp+3Bh], 0

    mov byte ptr [rsp+3Ch], "U"
    mov byte ptr [rsp+3Dh], "s"
    mov byte ptr [rsp+3Eh], "e"
    mov byte ptr [rsp+3Fh], "r"
    mov byte ptr [rsp+40h], "3"
    mov byte ptr [rsp+41h], "2"
    mov byte ptr [rsp+42h], "."
    mov byte ptr [rsp+43h], "d"
    mov byte ptr [rsp+44h], "l"
    mov byte ptr [rsp+45h], "l"
    mov byte ptr [rsp+46h], 0

    mov byte ptr [rsp+47h], "M"
    mov byte ptr [rsp+48h], "e"
    mov byte ptr [rsp+49h], "s"
    mov byte ptr [rsp+4Ah], "s"
    mov byte ptr [rsp+4Bh], "a"
    mov byte ptr [rsp+4Ch], "g"
    mov byte ptr [rsp+4Dh], "e"
    mov byte ptr [rsp+4Eh], "B"
    mov byte ptr [rsp+4Fh], "o"
    mov byte ptr [rsp+50h], "x"
    mov byte ptr [rsp+51h], "A"
    mov byte ptr [rsp+52h], 0

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


    mov qword ptr [rsp+60h], 0 ; bLoadRes
    mov qword ptr [rsp+68h], 0 ; bGetRes
    mov qword ptr [rsp+70h], rcx ;NumberOfFuncations


    xor rbx, rbx
    
    ; while rbx <= rcx
StartFindTwo:
    cmp rbx, [rsp+70h]
    ja findLGLoop

StartFindLoadLibraryA:
    mov ecx, dword ptr [r12+rbx*4h]
    add rcx, r10
    lea rdx, [rsp+20h]
    call MyStrcmp
    cmp rax, 0
    jne StartFindGetProcAddress
findLoadSuccess:
    mov qword ptr [rsp+60h], 1
    mov qword ptr [rsp+78h], rbx ; Load idx in Export


StartFindGetProcAddress:
    mov ecx, dword ptr [r12+rbx*4h]
    add rcx, r10
    lea rdx, [rsp+2Dh]
    call MyStrcmp
    cmp rax, 0
    jne CheckBothFound

findGetSuccess:
    mov qword ptr [rsp+68h], 1
    mov qword ptr [rsp+80h], rbx ; Get idx in Export

CheckBothFound:
    inc rbx
    cmp qword ptr [rsp+60h], 1
    jne StartFindTwo
    cmp qword ptr [rsp+68h], 1
    jne StartFindTwo

    

findLGLoop:
    cmp qword ptr [rsp+60h], 1
    jne ExitFindLoadAndGet
    mov rbx, qword ptr [rsp+78h]
    movzx rdi, word ptr [r13+rbx*2h]
    mov edi, dword ptr [r11+rdi*4h]
    add rdi, r10 
    mov r8, rdi ;LoadLibraryA
    cmp qword ptr [rsp+68h], 1
    jne ExitFindLoadAndGet
    mov rbx, qword ptr [rsp+80h]
    movzx rdi, word ptr [r13+rbx*2h]
    mov edi, dword ptr [r11+rdi*4h]
    add rdi, r10 
    mov r9, rdi ;GetProcAddress



ExitFindLoadAndGet:
    mov qword ptr [rsp+88h], r8
    mov qword ptr [rsp+90h], r9

    ; --- 调用 LoadLibraryA("User32.dll") ---
    lea rcx, [rsp+3Ch]              ; 第一个参数：指向 "User32.dll"
    mov r8, qword ptr [rsp+88h]
    call r8                         ; 调用 LoadLibraryA (地址在R8中)
                                    ; 此时 rsp 指向分配的开始位置，其后的0x20字节就是预留的影子空间

    ; --- 调用 GetProcAddress(hUser32, "MessageBoxA") ---
    mov rcx, rax                    ; 第一个参数：User32.dll的模块句柄 (来自上一步的RAX)
    lea rdx, [rsp+47h]              ; 第二个参数：指向 "MessageBoxA"
    mov r9, qword ptr [rsp+90h]
    call r9                         ; 调用 GetProcAddress (地址在R9中)
     
    ; rax 现在存放 MessageBoxA 的地址
    xor rcx, rcx
    xor rdx, rdx
    xor r8, r8
    xor r9, r9
    call rax

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