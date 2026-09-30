@echo off
rem Builds bin\LocalSubnetGuard.exe and runs the unit tests, using the .NET Framework 4.x
rem compiler that ships with Windows (no SDK needed).
setlocal
cd /d "%~dp0"
set CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe
if not exist "%CSC%" set CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe
set OPTS=-nologo -optimize+ -warnaserror+ -r:System.ServiceProcess.dll -r:Microsoft.CSharp.dll
if not exist bin mkdir bin

"%CSC%" %OPTS% -target:exe -out:bin\LocalSubnetGuard.exe LocalSubnetGuard.cs || exit /b 1
"%CSC%" %OPTS% -target:exe -out:bin\Tests.exe -main:LocalSubnetGuard.Tests.Runner LocalSubnetGuard.cs tests\Tests.cs || exit /b 1
bin\Tests.exe || exit /b 1
echo Built bin\LocalSubnetGuard.exe
