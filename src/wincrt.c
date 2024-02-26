/* This file is dedicated to the public domain. */

// TODO(opt): this feels like a sad implementation, can we do marginally better?
int memcmp(const void *x_, const void *y_, unsigned int sz) {
	const char *x = x_, *y = y_;
	for (unsigned int i = 0; i < sz; ++i) {
		if (x[i] > y[i]) return 1;
		if (x[i] < y[i]) return -1;
	}
	return 0;
}

void *memcpy(void *restrict x, const void *restrict y, unsigned int sz) {
#ifdef __clang__
	__asm__ volatile (
		"rep movsb\n" :
		"=D" (x), "=S" (y), "=c" (sz) :
		"0" (x), "1" (y), "2" (sz) :
		"memory"
	);
#else // terrible fallback just in case someone wants to use this with MSVC
	char *restrict xb = x; const char *restrict yb = y;
	for (unsigned int i = 0; i < sz; ++i) xb[i] = yb[i];
#endif
	return x;
}

// this was briefly needed at some point in debugging but seems to be gone again
// (hence crappy impl). if compiler starts calling memset with opts on, we
// should use a proper rep stosb impl as well
//void *memset(void *x, int c, unsigned int n) {
//	char *xb = x;
//	for (; n; ++xb, --n) *xb = c;
//	return x;
//}

// vi: sw=4 ts=4 noet tw=80 cc=80
