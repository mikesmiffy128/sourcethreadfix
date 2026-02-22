/*
 * Copyright © Michael Smith <mikesmiffy128@gmail.com>
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

#include "intdefs.h"
#include "x86.h"

#if defined(__clang__)
#define cold __attribute__((cold, noinline))
#define forceinline __attribute__((always_inline))
#elif defined(_MSC_VER)
#define cold __declspec(noinline)
#define forceinline __forceinline
#else
#define cold
#endif

static int len(const ushort *s) {
	int i = 0;
	for (; *s; ++s) ++i;
	return i;
}

// duped from sst mem.h
static forceinline int mem_cmp(const void *restrict x, const void *restrict y,
		unsigned int sz) {
#ifdef __clang__
	int a, b;
	__asm volatile (
		"xor eax, eax\n"
		"repz cmpsb\n"
		: "+D" (x), "+S" (y), "+c" (sz), "=@cca"(a), "=@ccb"(b)
		:
		: "ax", "memory"
	);
	return b - a;
#else // no msvc intrinsic for this apparently
	const char *x = x_, *y = y_;
	for (unsigned int i = 0; i < sz; ++i) {
		if (x[i] > y[i]) return 1;
		if (x[i] < y[i]) return -1;
	}
	return 0;
#endif
}

#ifdef __clang__
#define mem_copy_fixed __builtin_memcpy_inline
#else
// *terrible* fallback; should really be using Clang anyway.
static inline void mem_copy_fixed(char *restrict x, const char *restrict y,
		unsigned int sz) {
	char *restrict xb = x; const char *restrict yb = y;
	for (unsigned int i = 0; i < sz; ++i) xb[i] = yb[i];
}
#endif

static cold _Noreturn void diex(int status, const ushort *message) {
	MessageBoxW(0, message, L"Source Thread Fix wrapper error", 0);
	TerminateProcess((void *)-1, status);
	__assume(0);
}

static cold _Noreturn void _die(int status, ushort *message, int fmtoff) {
	FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), \
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), message + fmtoff,
			512 - fmtoff, 0); \
	diex(status, message); \
}
#define die(status, message) do { \
	ushort _buf[512]; \
	enum { _msgsz = (sizeof(message L": ") - 2) / 2 }; \
	mem_copy_fixed(_buf, message L": ", _msgsz * 2); /* bleh */ \
	_die(status, _buf, _msgsz); \
} while (0)

// IMPORTANT: I have lazily hardcoded offsets into this; change with caution!
static const uchar asminsns[] = {
	// Signature: ulong __stdcall hookdest_NtQuerySystemInformation(int class,
	//         void *info, ulong infolen, ulong *retlen)
	X86_PUSHEBP,				// push ebp
	X86_MOVMRW, 0xE5,			// mov ebp, esp
	X86_PUSHEDI,				// push edi
	X86_PUSHESI,				// push esi
	X86_MOVRMW, 0x75, 12,		// mov esi, dword ptr [ebp + 12]
	X86_MOVRMW, 0x7D, 8,		// mov edi, dword ptr [ebp + 8]
	X86_MISCMW, 0x75, 20,		// push dword ptr [ebp + 20]
	X86_MISCMW, 0x75, 16,		// push dword ptr [ebp + 16]
	X86_PUSHESI,				// push esi
	X86_PUSHEDI,				// push edi
	// eax = trampoline(class, info, infolen, retlen);
	X86_CALL, 20, 0, 0, 0,		// call +20 (trampoline)
	// if (c != SystemBasicInformation) return eax; // (c != 0)
	X86_TESTMRW, 0xFF,			// test edi edi
	X86_JNZ, 10,				// jne +10 (branch)
	// if (info->NumberOfProcessors > 24) info->NumberOfProcessors = 24;
	X86_ALUMI8, 0x7E, 40, 25,	// cmp byte ptr [esi + 40], 25
	X86_JL, 4,					// jl +4, (branch)
	X86_MOVMI8, 0x46, 40, 24,	// mov byte ptr [esi + 40], 24
	// branch:
	X86_POPESI,					// pop esi
	X86_POPEDI,					// pop edi
	X86_POPEBP,					// pop ebp
	X86_RETI16, 16, 0			// ret 16
	// trampoline:
	// (space in mapped page after insns)
};

static void readmem(void *proc, void *raddr, void *out, int n) {
	ulong nread;
	if (!ReadProcessMemory(proc, raddr, out, n, &nread)) {
		die(100, L"Couldn't read subprocess memory");
	}
}

static inline void rhook(void *proc, void *rtrampoline, void *rfunc,
		void *rtarget) {
	uchar trampoline[24];
	for (;;) {
		readmem(proc, rfunc, trampoline, 19);
		if (trampoline[0] != X86_JMPIW) break;
		s32 off = *(s32 *)(trampoline + 1);
		rfunc = (char *)rfunc + off + 5;
	}
	int len = 0;
	for (;;) {
		if (trampoline[len] == X86_CALL) {
			TerminateProcess(proc, 0); // XXX: annoying dupes
			diex(100, L"Unexpected call instruction in hooked function");
		}
		int ilen = x86_len(trampoline + len);
		if (ilen == -1) {
			TerminateProcess(proc, -1); // "
			diex(100, L"Unknown or invalid instruction in hooked function");
		}
		len += ilen;
		if (len >= 5) break;
		if (trampoline[len] == X86_JMPIW) {
			TerminateProcess(proc, -1); // "
			diex(100, L"Unexpected jump instruction in hooked function");
		}
	}
	unsigned char jmp[5];
	jmp[0] = X86_JMPIW;
	*(s32 *)(jmp + 1) = (char *)rtarget - (char *)rfunc - 5;
	WriteProcessMemory(proc, rfunc, jmp, sizeof(jmp), 0);
	trampoline[len] = X86_JMPIW;
	*(s32 *)(trampoline + len + 1) = (char *)rfunc - (char *)rtrampoline - 5;
	WriteProcessMemory(proc, rtrampoline, trampoline, len + 5, 0);
}

_Noreturn void __stdcall WinMainCRTStartup(void) {
	ushort name[MAX_PATH];
	ushort cmdline[32678];
	ushort *myargs = GetCommandLineW();
	bool quote = false, oddslash = false;
	for (; *myargs; ++myargs) {
		if (*myargs == '\\') {
			oddslash = !oddslash;
		}
		else {
			if (*myargs == '"') {
				if (!oddslash) quote = !quote;
			}
			else if ((*myargs == ' ' || *myargs == '\t') && !quote) {
				while (*++myargs == ' ' || *myargs == '\t');
				break;
			}
			oddslash = false;
		}
	}
	if (len(myargs) > 32767 - MAX_PATH - (sizeof("\"\"-insecure ") - 1)) {
		diex(1, L"Command line is too long");
	}
	int namelen = GetModuleFileNameW(0, name, MAX_PATH);
	if (namelen < sizeof("x.wrap.exe") - 1 ||
			mem_cmp(name + namelen - 9, L".wrap.exe", 18)) {
		diex(2, L"Wrapper name must end in .wrap.exe");
	}
	cmdline[0] = L'"';
	int i = 0;
	for (; i < namelen - 9; ++i) {
		cmdline[i + 1] = name[i]; // XXX: assuming no quotes etc. prolly fine?
	}
	mem_copy_fixed(name + i, L".exe", 5 * sizeof(*name)); // get rid of ".wrap"
	mem_copy_fixed(cmdline + i + 1, L".exe\" -insecure ", 16 * sizeof(*cmdline));
	const ushort *p = myargs; ushort *q = cmdline + i + 17;
	while (*q++ = *p++);
	PROCESS_INFORMATION info;
	STARTUPINFOW startinfo = {.cb = sizeof(startinfo)};
	// avoid any possible thunky weirdness using GPA rather than &func
	void *ntdll = GetModuleHandleW(L"ntdll.dll");
	if (!ntdll) {
		die(100, L"Couldn't get ntdll module; everything is on fire!");
	}
	void *qsiaddr = (void *)GetProcAddress(ntdll, "NtQuerySystemInformation");
	if (!qsiaddr) diex(100, L"Couldn't find GetSystemInfo symbol");
	if (!CreateProcessW(name, cmdline, 0, 0, 0, CREATE_SUSPENDED, 0, 0,
			&startinfo, &info)) {
		die(100, L"Couldn't start subprocess");
	}
	void *rmem = VirtualAllocEx(info.hProcess, 0, 4096,
			MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READ);
	if (!rmem) {
		TerminateProcess(info.hProcess, -1);
		die(100, L"Couldn't allocate memory in subprocess");
	}
	WriteProcessMemory(info.hProcess, rmem, asminsns, sizeof(asminsns), 0);
	rhook(info.hProcess, (char *)rmem + sizeof(asminsns), qsiaddr, rmem);
	ResumeThread(info.hThread);
	CloseHandle(info.hThread);
	WaitForSingleObject(info.hProcess, INFINITE);
	ulong status;
	GetExitCodeProcess(info.hProcess, &status);
	TerminateProcess((void *)-1, status);
	__assume(0);
}

// vi: sw=4 ts=4 noet tw=80 cc=80
