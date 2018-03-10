#pragma once

#include "types.h"
#include "peb.h"
#include "hash.h"
// http://www.alex-ionescu.com/Estoteric%20Hooks.pdf

void check_api_set(DWORD dwDllHash)
{
	PPEB peb = zl_peb();

#ifdef _WIN64
	PAPI_SET_NAMESPACE_ARRAY pApiSetMap = (PAPI_SET_NAMESPACE_ARRAY)(((PCHAR)peb) + ZEROLOAD_APISETMAP_OFFSET_X64);
#else
	PAPI_SET_NAMESPACE_ARRAY pApiSetMap = (PAPI_SET_NAMESPACE_ARRAY)(((PCHAR)peb) + ZEROLOAD_APISETMAP_OFFSET_X86);
#endif
	for (size_t i = 0; i < pApiSetMap->Count; i++)
	{
		wchar_t apiNameBuf[255] = { 0 };
		wchar_t apiHostNameBuf[255] = { 0 };
		size_t oldValueLen = 0;

		PAPI_SET_NAMESPACE_ENTRY pDescriptor = (PAPI_SET_NAMESPACE_ENTRY)((PUCHAR)pApiSetMap + pApiSetMap->End + i * sizeof(API_SET_NAMESPACE_ENTRY));
		PAPI_SET_VALUE_ARRAY pHostArray = (PAPI_SET_VALUE_ARRAY)((PUCHAR)pApiSetMap + pApiSetMap->Start + sizeof(API_SET_VALUE_ARRAY) * pDescriptor->Size);

		PAPI_SET_VALUE_ENTRY pHost = (PAPI_SET_VALUE_ENTRY)((PUCHAR)pApiSetMap + pHostArray->DataOffset);
		PVOID pHostName = (PUCHAR)pApiSetMap + pHost->ValueOffset;

		if (zl_compute_hash(pHostName, pHost->ValueLength) == dwDllHash)
		{
			PVOID pApiName = (PUCHAR)pApiSetMap + pHostArray->NameOffset;
			DWORD pApiLength = pHostArray->NameLength;
		}
	}
	}