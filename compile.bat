:: This file is dedicated to the public domain.
@echo off

llvm-rc /nologo /r /fo tmp.res src/exe.rc
clang-cl -m32 -mno-sse -fuse-ld=lld -flto -O1 -GR- -GS- -Gs9999999 -EHa- -Oi ^
-Fehl2.wrap.exe -W3 -Wpedantic -DWIN32_LEAN_AND_MEAN -DNOMINMAX ^
src/injected.c src/wincrt.c src/wrap.c src/x86.c ^
-link -nodefaultlib -subsystem:windows,6.0 -stack:0x10000,0x10000 -fixed:no ^
-dynamicbase -Brepro ^
kernel32.lib user32.lib tmp.res
del tmp.res & exit /b %errorlevel%

:: vi: sw=4 ts=4 noet tw=80 cc=80
