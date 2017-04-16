# zeroload

Improvements to traditional reflective injection:

- Any .dll imports not in original .exe are also reflective loaded
    - They will not show up in PEB_LDR_DATA lists
- No C runtime, smaller executable size
- Proper DLL forwarder chain parsing
- Reusable, easier to read loader code
- fn1va_32 hashing algorithm for better collision safety
