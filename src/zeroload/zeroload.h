#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h>
#include <intrin.h>

#pragma intrinsic(_ReturnAddress)
#pragma intrinsic(strcmp)
#pragma intrinsic(memcpy)
#pragma intrinsic(memset)

// in case someone found this useful
#define DLL_QUERY_HMODULE		6

// function typedefs
typedef HMODULE	(WINAPI * FnLoadLibraryA_t)(LPCSTR);
typedef FARPROC	(WINAPI * FnGetProcAddress_t)(HMODULE, LPCSTR);
typedef LPVOID	(WINAPI * FnVirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL	(WINAPI * FnDllMain_t)(HINSTANCE, DWORD, LPVOID);
typedef DWORD	(NTAPI  * FnNtFlushInstructionCache_t)(HANDLE, PVOID, ULONG);


LPBYTE zeroload_read_library_file(const char *szLibrary);

LPBYTE __forceinline zeroload_load_image(LPBYTE lpBaseAddr);

// struct typedefs
typedef struct
{
	WORD	offset : 12;
	WORD	type : 4;
} ZEROLOAD_IMAGE_RELOC, *PZEROLOAD_IMAGE_RELOC;

// see zeroload_compute_hash()
// DLLs we need loaded to do anything usefull...
#define ZEROLOAD_HASH_KERNEL32			0x29cdd463
#define ZEROLOAD_HASH_NTDLL				0x145370bb

#define ZEROLOAD_HASH_LOADLIBRARYA		0xe96ce9ef
#define ZEROLOAD_HASH_VIRTUALALLOC		0x38e87001