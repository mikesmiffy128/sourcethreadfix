/*
 * Copyright © 2024 Michael Smith <mikesmiffy128@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED “AS IS” AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef INC_FAKEIAT_H
#define INC_FAKEIAT_H

struct _SYSTEM_INFO;

typedef int (*__stdcall _iat_FlushInstructionCache_func)(void *, const void *,
		unsigned long);
typedef void (*__stdcall _iat_GetSystemInfo_func)(struct _SYSTEM_INFO *);
typedef int (*__stdcall _iat_VirtualProtect_func)(void *, unsigned long,
		unsigned long, unsigned long *);

// Because this is one EXE (not a DLL), injecting it with LoadLibrary doesn't
// fill out the IAT properly, causing crashes when API functions are used. We
// _could_ just manually populate/fix up the IAT, but that's kind of a pain in
// the arse. Instead, we use this poor-man's IAT to pass down literally three
// functions that are used inside of the child process' address space.
extern struct _fakeiat {
	_iat_FlushInstructionCache_func FlushInstructionCache;
	_iat_GetSystemInfo_func GetSystemInfo;
	_iat_VirtualProtect_func VirtualProtect;
} IAT;

#ifdef FAKEIAT_DEFINES
#define FlushInstructionCache (IAT.FlushInstructionCache)
#define GetSystemInfo (IAT.GetSystemInfo)
#define VirtualProtect (IAT.VirtualProtect)
#endif

#endif
