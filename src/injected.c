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

#include <stdbool.h>
#include <Windows.h>

#define FAKEIAT_DEFINES
#include "fakeiat.h"
#include "intdefs.h"
#include "x86.h"

// The stuff in this file gets called in the address space of the child process!
// Because we're an EXE, our IAT doesn't get filled properly, so in order to
// call kernel32 functions without crashing, make sure they're in the fake IAT.
// See fakeiat.h and wrap.c.

__declspec(align(4096))
static uchar trampoline[4096]; // has to be a whole page, obviously

// simplified version of the usual hook.c code since there's only a single
// function to hook and no need to unhook
static bool hook(void *func_, void *target) {
	ulong old;
	if (!VirtualProtect(trampoline, sizeof(trampoline),
			PAGE_EXECUTE_READWRITE, &old)) {
		return false;
	}
	uchar *func = func_;
	while (*func == X86_JMPIW) func += *(int *)(func + 1) + 5;
	if (!VirtualProtect(func, 5, PAGE_EXECUTE_READWRITE, &old)) return false;
	int len = 0;
	for (;;) {
		if (func[len] == X86_CALL) return false;
		int ilen = x86_len(func + len);
		if (ilen == -1) return false;
		len += ilen;
		if (len >= 5) break;
		if (func[len] == X86_JMPIW) return false;
	}
	memcpy(trampoline, func, len);
	trampoline[len] = X86_JMPIW;
	uint diff = func - (trampoline + 5); // goto the continuation
	memcpy(trampoline + len + 1, &diff, 4);
	diff = (uchar *)target - (func + 5); // goto the hook target
	func[0] = X86_JMPIW;
	memcpy(func + 1, &diff, 4);
	// -1 is the current process, and it's a constant in the WDK, so it's
	// assumed we can safely avoid the useless GetCurrentProcess call
	FlushInstructionCache((void *)-1, func, 5);
	return true;
}

typedef void (*__stdcall GetSystemInfo_func)(SYSTEM_INFO *info);
#define orig_GetSystemInfo ((GetSystemInfo_func)trampoline)
static void __stdcall hook_GetSystemInfo(SYSTEM_INFO *info) {
	orig_GetSystemInfo(info);
	// Here's where the magic happens! NOTE: the actual limit is a bit higher
	// than this, but there's probably not much reason to go over this either.
	if (info->dwNumberOfProcessors > 24) info->dwNumberOfProcessors = 24;
}

__declspec(noinline) int __stdcall injectedentry(int unused) {
	return hook((void *)GetSystemInfo, (void *)&hook_GetSystemInfo);
}
