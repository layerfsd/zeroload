#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h>
#include <intrin.h>

//
// below are options you can define, they will set the default pState of the export
// pState = zl_state_init(ZEROLOAD_REFLECT_ALL, ZEROLOAD_STOPPAGING, ZEROLOAD_MAX_DEPTH)
//

// if either is defined, we will rename the reflective loader export
#ifndef ZEROLOAD_EXPORT_NAME
#ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
#define ZEROLOAD_EXPORT_NAME ReflectiveLoader
#else
#define ZEROLOAD_EXPORT_NAME zeroload
#endif
#endif

// maximum recursion for reflective loading
#ifndef ZEROLOAD_MAX_DEPTH
#define ZEROLOAD_MAX_DEPTH 100
#endif

/* APISetMap offset into PEB */
#ifndef ZEROLOAD_APISETMAP_OFFSET_X64
#define ZEROLOAD_APISETMAP_OFFSET_X64 104
#endif

#ifndef ZEROLOAD_APISETMAP_OFFSET_X64
#define ZEROLOAD_APISETMAP_OFFSET_X64 56
#endif

// we will not reflectively load if the traditional method is defined, just in case
#ifndef ZEROLOAD_REFLECT_ALL
#ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
#define ZEROLOAD_REFLECT_ALL FALSE
#else
#define ZEROLOAD_REFLECT_ALL TRUE
#endif
#endif

#ifndef ZEROLOAD_STOP_PAGING
#ifdef ENABLE_STOPPAGING
#define ZEROLOAD_STOPPAGING TRUE
#else
#define ZEROLOAD_STOPPAGING FALSE
#endif
#endif

//
// end options
//

#define ZLAPI __forceinline

// in case someone found this useful
#define DLL_METASPLOIT_ATTACH	4
#define DLL_METASPLOIT_DETACH	5
#define DLL_QUERY_HMODULE		6

// metasploit stuff
#define EXITFUNC_SEH		0xEA320EFE
#define EXITFUNC_THREAD		0x0A2A1DE0
#define EXITFUNC_PROCESS	0x56A2B5F0

// see zeroload_compute_hash()
// DLLs we need loaded to do anything usefull...
#define ZEROLOAD_HASH_KERNEL32			0x29cdd463
#define ZEROLOAD_HASH_NTDLL				0x145370bb

// these are necessary for all options
#define ZEROLOAD_HASH_VIRTUALALLOC		0x38e87001
#define ZEROLOAD_HASH_VIRTUALFREE		0x81178a12
#define ZEROLOAD_HASH_NTFLUSHINSTRUCTIONCACHE	0x77daaee9

// only called in case of pState->bStopPaging
#define ZEROLOAD_HASH_VIRTUALLOCK		0x1da67973	
#define ZEROLOAD_HASH_VIRTUALUNLOCK		0xd7844b38

// only called to increase refcount on pre-loadeds, !pstate->bStopPaging
#define ZEROLOAD_HASH_LOADLIBRARYA		0xe96ce9ef	

// only called in case of pState->bReflectAll
#define ZEROLOAD_HASH_SEARCHPATHA		0xa5e185e9  
#define ZEROLOAD_HASH_CREATEFILEA		0xe84b3a8e
#define ZEROLOAD_HASH_GETFILESIZE		0x7c072ed8
#define ZEROLOAD_HASH_READFILE			0xbc5c02c3	
#define ZEROLOAD_HASH_CLOSEHANDLE		0x00fef545

#pragma intrinsic(_ReturnAddress)
#pragma intrinsic(memcmp)
#pragma intrinsic(memset)
//#pragma intrinsic(memmove)
//#pragma intrinsic(memcmp)
// compilers love to use memcpy, memset, memmove, and memcmp
// even when you ask to inline them with intrinsics...
// it may be required to write a minimal C library to fix link errors in code
//extern void * __cdecl memset(void * dest, int c, size_t num);
//extern void * __cdecl memcpy(void * dest, const void * src, size_t num);
//extern void * __cdecl memmove (void * dest, const void * src, size_t num);.
//extern int __cdecl memcmp(const void * ptr1, const void * ptr2, size_t num);

// function typedefs
typedef HMODULE	(WINAPI * FnLoadLibraryA_t)(LPCSTR);
typedef FARPROC	(WINAPI * FnGetProcAddress_t)(HMODULE, LPCSTR);
typedef LPVOID	(WINAPI * FnVirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL	(WINAPI * FnVirtualFree_t)(LPVOID, SIZE_T, DWORD);
typedef BOOL	(WINAPI * FnVirtualLock_t)(LPVOID, SIZE_T);
typedef BOOL	(WINAPI * FnVirtualUnlock_t)(LPVOID, SIZE_T);
typedef HANDLE	(WINAPI * FnCreateFileA_t)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef DWORD	(WINAPI * FnGetFileSize_t)(HANDLE, LPDWORD);
typedef BOOL	(WINAPI * FnCloseHandle_t)(HANDLE);
typedef DWORD	(WINAPI * FnSearchPathA_t)(LPCSTR, LPCSTR, LPCSTR, DWORD, LPSTR, LPSTR *);
typedef BOOL	(WINAPI * FnReadFile_t)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL	(WINAPI * FnDllMain_t)(HINSTANCE, DWORD, LPVOID);
typedef DWORD	(NTAPI  * FnNtFlushInstructionCache_t)(HANDLE, PVOID, ULONG);

// Thanks Blackbone and Sheksa for the structs
typedef struct _API_SET_VALUE_ENTRY
{
	ULONG Flags;
	ULONG NameOffset;
	ULONG NameLength;
	ULONG ValueOffset;
	ULONG ValueLength;
} API_SET_VALUE_ENTRY, *PAPI_SET_VALUE_ENTRY;

typedef struct _API_SET_VALUE_ARRAY
{
	ULONG Flags;
	ULONG NameOffset;
	ULONG Unk;
	ULONG NameLength;
	ULONG DataOffset;
	ULONG Count;
} API_SET_VALUE_ARRAY, *PAPI_SET_VALUE_ARRAY;

typedef struct _API_SET_NAMESPACE_ENTRY
{
	ULONG Limit;
	ULONG Size;
} API_SET_NAMESPACE_ENTRY, *PAPI_SET_NAMESPACE_ENTRY;

typedef struct _API_SET_NAMESPACE_ARRAY
{
	ULONG Version;
	ULONG Size;
	ULONG Flags;
	ULONG Count;
	ULONG Start;
	ULONG End;
	ULONG Unk[2];
} API_SET_NAMESPACE_ARRAY, *PAPI_SET_NAMESPACE_ARRAY;

// struct typedefs
typedef struct _ZEROLOAD_IMAGE_RELOC
{
	WORD	offset : 12;
	WORD	type : 4;
} ZEROLOAD_IMAGE_RELOC, *PZEROLOAD_IMAGE_RELOC;

// single-linked list of reflectively-loaded DLLs
typedef struct _ZEROLOAD_DLL
{
	struct _ZEROLOAD_DLL *pNext;
	LPBYTE lpDllBase;
	DWORD dwSize;
	DWORD dwHash;
} ZEROLOAD_DLL, *PZEROLOAD_DLL;

typedef struct _ZEROLOAD_STATE
{
	PZEROLOAD_DLL pLoadedList;
	
	BOOL bStopPaging;
	BOOL bReflectAll;

	DWORD dwDepth;
	DWORD dwMaxDepth;

	FnLoadLibraryA_t	pLoadLibraryA;
	FnSearchPathA_t		pSearchPathA;

	FnVirtualAlloc_t	pVirtualAlloc;
	FnVirtualFree_t		pVirtualFree;
	FnVirtualLock_t		pVirtualLock;
	FnVirtualUnlock_t	pVirtualUnlock;

	FnCreateFileA_t		pCreateFileA;
	FnGetFileSize_t		pGetFileSize;
	FnReadFile_t		pReadFile;
	FnCloseHandle_t		pCloseHandle;
	
	FnNtFlushInstructionCache_t pNtFlushInstructionCache;
} ZEROLOAD_STATE, *PZEROLOAD_STATE;
