:: This file is dedicated to the public domain.
@echo off

:: NOTE: requires 7-zip, either in the default installation dir or %SEVENZIP%

call compile.bat || exit /B
if not exist release\ md release
if "%SEVENZIP%"=="" set SEVENZIP=C:\Program Files\7-Zip\7z.exe
setlocal EnableDelayedExpansion
for /F "tokens=* usebackq" %%x IN (`^(echo VERSION_MAJOR ^& echo VERSION_MINOR^) ^| ^
		clang -x c -E -include src\version.h - ^| findstr /v #`) do (
	:: dumb but works:
	if "!major!"=="" set major=%%x
	set minor=%%x
)
setlocal DisableDelayedExpansion
set name=threadfix-v%major%.%minor%-win32
md TEMP-%name% || exit /B
copy hl2.wrap.exe TEMP-%name%\hl2.wrap.exe || exit /B
copy dist\LICENCE-threadfix TEMP-%name%\LICENCE-threadfix || exit /B
:: using midnight on release day to make zip deterministic! change on next release!
powershell (Get-Item TEMP-%name%\hl2.wrap.exe).LastWriteTime = new-object DateTime 2024, 2, 26, 0, 0, 0
powershell (Get-Item TEMP-%name%\LICENCE-threadfix).LastWriteTime = new-object DateTime 2024, 2, 26, 0, 0, 0
pushd TEMP-%name%
"%SEVENZIP%" a -mtc=off %name%.zip hl2.wrap.exe LICENCE-threadfix || exit /B
move %name%.zip ..\release\%name%.zip
popd
rd /s /q TEMP-%name%\ || exit /B
