:: 
:: Copyright (c) 2016 Jesse Nicholson.
:: 
:: This file is part of Http Filtering Engine.
:: 
:: Http Filtering Engine is free software: you can redistribute it and/or
:: modify it under the terms of the GNU General Public License as published
:: by the Free Software Foundation, either version 3 of the License, or (at
:: your option) any later version.
:: 
:: In addition, as a special exception, the copyright holders give
:: permission to link the code of portions of this program with the OpenSSL
:: library.
:: 
:: You must obey the GNU General Public License in all respects for all of
:: the code used other than OpenSSL. If you modify file(s) with this
:: exception, you may extend this exception to your version of the file(s),
:: but you are not obligated to do so. If you do not wish to do so, delete
:: this exception statement from your version. If you delete this exception
:: statement from all source files in the program, then also delete it
:: here.
:: 
:: Http Filtering Engine is distributed in the hope that it will be useful,
:: but WITHOUT ANY WARRANTY; without even the implied warranty of
:: MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
:: Public License for more details.
:: 
:: You should have received a copy of the GNU General Public License along
:: with Http Filtering Engine. If not, see <http://www.gnu.org/licenses/>.
:: 

:: NOTICE! You need to have nasm (for 32 bit) installed and just in case 
:: you don't already have it in the path, we'll temporarily add it to the 
:: path here. If you don't have this installed to the default directory, 
:: this script and overall compilation will fail. 

@echo off

:: Set OPENSSL_VERSION to the extracted folder name, which includes the 
:: version. So, as an example, in 
:: HTTP_FILTER_ENGINE_ROOT_DIR\deps\openssl, you should have extracted lets 
:: say Open SSL 1.0.2d. So you'll have 
:: HTTP_FILTER_ENGINE_ROOT_DIR\deps\openssl\openssl-1.0.2d\SOURCES. 
:: Therefore, set OPENSSL_VERSION to "openssl-1.0.2d" like so:
:: OPENSSL_VERSION=openssl-1.0.2d 
set OPENSSL_VERSION=

:: Make sure the variables have been set.
if [%OPENSSL_VERSION%] == [] GOTO RequiresSetup

:: Add NASM default install directory to the PATH temporarily.
set PATH=%PATH%;%LOCALAPPDATA%\nasm

:: Invoke the 32 bit Visual Studio command prompt environment, for 32 
:: bit build tool stuff to be setup. If you have installed VS 2015 to a 
:: non-standard place, or have an older version of VS, you will need to 
:: change this line. 
call "C:\Program Files (x86)\Microsoft Visual Studio 14.0\Common7\Tools\vsvars32.bat"

:: Change the current directory to the x86 OpenSSL release source directory.
cd ..\..\deps\openssl\%OPENSSL_VERSION%\src-msvc-x86-release

:: Configure OpenSSL build to omit weak and patented code, release.
perl Configure VC-WIN32 no-idea no-mdc2 no-rc5 no-comp no-ssl2 no-ssl3 threads --prefix="%cd%\..\..\msvc\Releasex86"

:: Do the release build.
call ms\do_nasm.bat
nmake -f ms\ntdll.mak
nmake -f ms\ntdll.mak install

:: Change the current directory to the x86 OpenSSL debug source directory.
cd ..\src-msvc-x86-debug

:: Configure OpenSSL build to omit weak and patented code, release.
perl Configure debug-VC-WIN32 no-idea no-mdc2 no-rc5 no-comp no-ssl2 no-ssl3 threads --prefix="%cd%\..\..\msvc\Debugx86"

:: Do the debug build.
call ms\do_nasm.bat
nmake -f ms\ntdll.mak
nmake -f ms\ntdll.mak install

:: Rename output folders. OpenSSL build can't deal with spaces, in 2015.
:: Delete the folders first, if they exist.
rmdir /S /Q "%cd%\..\..\msvc\Debug x86"
rmdir /S /Q "%cd%\..\..\msvc\Release x86"
MOVE /Y "%cd%\..\..\msvc\Debugx86" "%cd%\..\..\msvc\Debug x86"
MOVE /Y  "%cd%\..\..\msvc\Releasex86" "%cd%\..\..\msvc\Release x86"

:: Copy debug symbols to the debug output dir. You want these copied to the 
:: bin directory, right beside the DLL files they are for, because this is
:: where the debugger will search for the symbols by default.
xcopy /Y "%cd%\out32dll.dbg\libeay32.pdb" "%cd%\..\..\msvc\Debug x86\bin\"
xcopy /Y "%cd%\out32dll.dbg\ssleay32.pdb" "%cd%\..\..\msvc\Debug x86\bin\"

:: Sometimes, because of things like A/V screwing around, copying/generating 
:: openssl.exe will fail, screwing up copying our successful lib build. So, 
:: we'll do a copy of the lib and dll files manually, just in case. The libs
:: are all we care about anyway.We'll also call mkdir just to make sure that
:: the directories exist.
mkdir "%cd%\..\..\msvc\Debug x86\"
mkdir "%cd%\..\..\msvc\Debug x86\lib"
mkdir "%cd%\..\..\msvc\Debug x86\bin"
mkdir "%cd%\..\..\msvc\Debug x86\include"
mkdir "%cd%\..\..\msvc\Debug x86\ssl"
mkdir "%cd%\..\..\msvc\Release x86\"
mkdir "%cd%\..\..\msvc\Release x86\lib"
mkdir "%cd%\..\..\msvc\Release x86\bin"
mkdir "%cd%\..\..\msvc\Release x86\include"
mkdir "%cd%\..\..\msvc\Release x86\ssl"

:: Copy debug output.
xcopy /Y "%cd%\out32dll.dbg\libeay32.lib" "%cd%\..\..\msvc\Debug x86\lib\"
xcopy /Y "%cd%\out32dll.dbg\ssleay32.lib" "%cd%\..\..\msvc\Debug x86\lib\"
xcopy /Y "%cd%\out32dll.dbg\libeay32.dll" "%cd%\..\..\msvc\Debug x86\bin\"
xcopy /Y "%cd%\out32dll.dbg\ssleay32.dll" "%cd%\..\..\msvc\Debug x86\bin\"
xcopy /Y /E "%cd%\inc32" "%cd%\..\..\msvc\Debug x86\include\"
xcopy /Y "%cd%\apps\openssl.cnf" "%cd%\..\..\msvc\Debug x86\ssl\"

:: Change to release again, so we can copy those as well.
cd ..\src-msvc-x86-release

:: Copy release output.
xcopy /Y "%cd%\out32dll.dbg\libeay32.lib" "%cd%\..\..\msvc\Release x86\lib\"
xcopy /Y "%cd%\out32dll.dbg\ssleay32.lib" "%cd%\..\..\msvc\Release x86\lib\"
xcopy /Y "%cd%\out32dll.dbg\libeay32.dll" "%cd%\..\..\msvc\Release x86\bin\"
xcopy /Y "%cd%\out32dll.dbg\ssleay32.dll" "%cd%\..\..\msvc\Release x86\bin\"
xcopy /Y /E "%cd%\inc32" "%cd%\..\..\msvc\Release x86\include\"
xcopy /Y "%cd%\apps\openssl.cnf" "%cd%\..\..\msvc\Release x86\ssl\"

:: Change back to the scripts directory.
cd ..\..\..\..\scripts\win

:: All Done.
exit /B

:: This will print out help information to the console to assist the 
:: user in correctly configuring the script in the event that the variables 
:: were not setup. 
:RequiresSetup
echo. & echo Please edit this batch file to have the following variables set correctly: & echo.
echo 	OPENSSL_VERSION - Set this to the name of the Open SSL source directory, the folder which includes the version number in it. & echo.
echo. & echo See script comments for more details.
timeout 10
exit /B