#pragma once

#include "types.h"

// this is a variation of the fnv1a_32 hash algorithm, but keeping the original primes,
// changed to allow both unicode and char*, slower but same distribution for ascii text
DWORD ZLAPI zl_compute_hash(const void *input, DWORD len)
{
	const unsigned char *data = (const unsigned char *)input;

	DWORD hash = 2166136261;

	while (1)
	{
		char current = *data;
		if (len == 0)
		{
			if (*data == 0)
				break;
		}
		else
		{
			if ((DWORD)(data - (const unsigned char *)input) >= len)
				break;

			if (*data == 0)
			{
				++data;
				continue;
			}
		}

		// toupper
		if (current >= 'a')
			current -= 0x20;

		hash ^= current;
		hash *= 16777619;

		++data;
	}

	return hash;
}
