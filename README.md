# zeroload

** WORK IN PROGRESS **

Improvements to traditional reflective injection:

- Any .dll imports not in original .exe are also reflective loaded
    - They will not show up in PEB_LDR_DATA lists
    - Normally, dependancy DLLs with Fewer method Reflective Injection are loaded with LoadLibraryA...
        - With zeroload, **ALL** dependencies are reflectively loaded (hence, zero "rogue" DLLs)
- No C runtime, smaller executable size
- Proper DLL forwarder chain parsing
- Reusable, easier to read loader code (broken out __forceinline functions vs. giant function)
- fnv1a_32 hashing algorithm for better collision safety

## What's the Big Idea?
In the case of normal Reflective DLL injection (Fewer method), only the reflective DLL is loaded via a stealthy method. Its dependency DLLs are loaded via LoadLibrary... this means means that if you inject a reverse shell DLL into notepad.exe, it will load suspicious things like ws2_32.dll and other DLLs into the process.

zeroload is an attempt to completely emulate the Windows loader. If you inject a zeroload DLL into notepad.exe, -ALL- import DLL's should be loaded reflectively as well and hidden from basic tooling.

## What's the Complication?
Before Windows 7ish this should be relatively straightforward (although some DLLs may be finnicky). However in the modern era, there are "API Sets", which are sort of a new DLL forwarding method. Just because something says its in user32.dll, again, doesn't mean it really is. Instead, the kernel performs a mapping to API Set DLLs and ends up loading hundreds of DLLs, each with a few functions each.

Alex Ionescu and others have proven these structures can be parsed from user mode (see: http://www.alex-ionescu.com/Estoteric%20Hooks.pdf). So it would seem we have everything needed to emulate the Windows loader for most DLLs.

## Where's the Code At?
Right now the code could be a drop-in replacement for normal Reflective DLL injection (indeed, the project is set up to just work as such, with the same defines etc.). This includes the Metasploit additions to the Fewer method.

So Fewer method is done. What's not done is the whole point... zero loading. API Set parsing code is implemented. There is a little bit of glue and debugging that needs to happen to put it all together. See: ZEROLOAD_STATE.bReflectAll

## Where's the Rabbit Hole start?
- https://github.com/zerosum0x0/zeroload/blob/master/zdi/dll/zeroload/zeroload.c#L8
- https://github.com/zerosum0x0/zeroload/blob/master/zdi/dll/zeroload/load.h#L72
