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

#include "fakeiat.h"
#include "intdefs.h"

extern struct HINSTANCE__ __ImageBase;

struct _fakeiat IAT;

static int len(const ushort *s) {
	int i = 0;
	for (; *s; ++s) ++i;
	return i;
}

static _Noreturn void die(int status, const ushort *message) {
	MessageBoxW(0, message, L"Thread fix wrapper error", 0);
	ExitProcess(status);
}

__declspec(noinline) int __stdcall injectedentry(int unused); // injected.c

static void *rpc(void *proc, void *rfunc, void *rparam, const ushort *errstr) {
	void *rthread = CreateRemoteThread(proc, 0, 32768,
			(LPTHREAD_START_ROUTINE)rfunc, rparam, 0, 0);
	if (!rthread) {
		TerminateProcess(proc, -1);
		die(100, errstr);
	}
	WaitForSingleObject(rthread, INFINITE);
	void *ret;
	GetExitCodeThread(rthread, (ulong *)&ret);
	return ret;
}

// main EXE entry point. this seems not to get called when we're LoadLibrary'd!
_Noreturn void __stdcall WinMainCRTStartup(void) {
	ushort name[MAX_PATH], origname[MAX_PATH];
	ushort cmdline[32678];
	ushort *myargs = GetCommandLineW();
	bool quote = false, oddslash = false;
	for (;; ++myargs) {
		if (*myargs == '\0') die(1, L"Unexpected end of command line");
		if (*myargs == '\\') {
			oddslash = !oddslash;
		}
		else {
			if (*myargs == '"') { if (!oddslash) quote = !quote; }
			else if ((*myargs == ' ' || *myargs == '\t') && !quote) break;
			oddslash = false;
		}
	}
	while (*++myargs == ' ' || *myargs == '\t');
	if (len(myargs) > 32767 - MAX_PATH - sizeof("\"\"-steam -insecure ") - 1) {
		die(1, L"Command line is too long");
	}
	int namelen = GetModuleFileNameW(0, name, MAX_PATH);
	if (namelen < sizeof("x.wrap.exe") - 1 ||
			memcmp(name + namelen - 9, L".wrap.exe", 9)) {
		die(2, L"Wrapper name must end in .wrap.exe");
	}
	cmdline[0] = L'"';
	int i = 0;
	for (; i < namelen - 9; ++i) {
		origname[i] = name[i];
		cmdline[i + 1] = name[i]; // XXX: assuming no quotes etc. prolly fine?
	}
	memcpy(origname + i, L".exe", 4 * sizeof(*origname));
	memcpy(cmdline + i + 1, L".exe\" -steam -insecure ", 23 * sizeof(*cmdline));
	const ushort *p = myargs; ushort *q = cmdline + i + 24;
	do *q++ = *p; while (*p++);
	PROCESS_INFORMATION info;
	STARTUPINFOW startinfo = {.cb = sizeof(startinfo)};
	if (!CreateProcessW(origname, cmdline, 0, 0, 0, CREATE_SUSPENDED, 0, 0,
			&startinfo, &info)) {
		die(100, L"Couldn't start subprocess");
	}
	// avoid any possible thunky weirdness using GPA rather than &LoadLibraryW
	void *k32 = GetModuleHandleW(L"kernel32.dll");
	if (!k32) die(100, L"Couldn't get kernel32 module; everything is on fire!");
	void *lladdr = (void *)GetProcAddress(k32, "LoadLibraryW");
	int namebytes = (namelen + 1) * sizeof(*name);
	void *rmem = VirtualAllocEx(info.hProcess, 0, namebytes,
			MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!rmem) {
		TerminateProcess(info.hProcess, -1);
		die(100, L"Couldn't allocate memory in subprocess");
	}
	WriteProcessMemory(info.hProcess, rmem, name, namebytes, 0);
	void *rdll = rpc(info.hProcess, lladdr, rmem,
			L"Couldn't call LoadLibrary in subprocess");
	if (!rdll) {
		TerminateProcess(info.hProcess, -1);
		die(100, L"LoadLibrary call in subprocess returned an error");
	}
	// injectentry will be at the same offset, just a different base
	void *rfunc = (char *)rdll + ((char *)&injectedentry - (char *)&__ImageBase);
	VirtualFreeEx(info.hProcess, rmem, namebytes, MEM_RELEASE);
	// Fill out the "fake IAT" table and use WPM to copy it to the injected side
	// of things. See fakeiat.h for more exposition.
#define PUTIAT(f) IAT.f = (_iat_##f##_func)GetProcAddress(k32, #f)
	PUTIAT(GetSystemInfo);
	PUTIAT(FlushInstructionCache);
	PUTIAT(VirtualProtect);
#undef PUTIAT
	void *riat = (char *)rdll + ((char *)&IAT - (char *)&__ImageBase);
	WriteProcessMemory(info.hProcess, riat, &IAT, sizeof(IAT), 0);
	if (!rpc(info.hProcess, rfunc, 0,
			L"Couldn't call injected entry point in subprocess")) {
		die(100, L"Injected code failed to hook GetSystemInfo");
	}
	ResumeThread(info.hThread);
	CloseHandle(info.hThread);
	WaitForSingleObject(info.hProcess, INFINITE);
	ulong status;
	GetExitCodeProcess(info.hProcess, &status);
	ExitProcess(status);
}
