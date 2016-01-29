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

@echo off

:: Set BOOST_VERSION to the extracted folder name, which includes the 
:: boost version. So, as an example, in 
:: HTTP_FILTER_ENGINE_ROOT_DIR\deps\boost, you should have extracted lets say 
:: Boost 1.59. So you'll have 
:: HTTP_FILTER_ENGINE_ROOT_DIR\deps\boost\boost_1_59_0\SOURCES. Therefore, 
:: set BOOST_VERSION to "boost_1_59_0" like so:
:: BOOST_VERSION=boost_1_59_0
set BOOST_VERSION=boost_1_60_0

:: Again, BZIP_VERSION isn't just the version number, but the name 
:: including the version number. This is how the folders of unizipped 
:: archives are, so when you download and extract bzip2, you'll have a 
:: folder named, for example, "bzip2-1.0.6". Just like with BOOST_VERSION, 
:: you would have put this sources folder inside 
:: HTTP_FILTER_ENGINE_ROOT_DIR\deps\bzip2\, resulting in 
:: HTTP_FILTER_ENGINE_ROOT_DIR\deps\bzip2\bzip2-1.0.6\SOURCES. In this case, 
:: you'd set the variable like so:
:: BZIP_VERSION=bzip2-1.0.6
set BZIP_VERSION=bzip2-1.0.6

:: Exactly the same process as BOOST_VERSION and BZIP_VERSION. See 
:: comments on them. - zlib-1.2.8
set ZLIB_VERSION=zlib-1.2.8

:: Checking to make sure that the required variables have been set, if 
:: not, jump to the end and warn the user that the script requires minor 
:: configuration.
if [%BOOST_VERSION%] == [] GOTO RequiresSetup
if [%BZIP_VERSION%] == [] GOTO RequiresSetup
if [%ZLIB_VERSION%] == [] GOTO RequiresSetup

:: Set the total number of logical cores for compilation to use. This 
:: will default to the max (total detected), but you can adjust this.
set COMPILATION_NUMCORES=%NUMBER_OF_PROCESSORS%

:: Change to the boost root directory.
cd ..\..\deps\boost\%BOOST_VERSION%

:: First, build bjam, in case it isn't already built.
call "bootstrap.bat"

:: Force deletion of bin folder, since bjam --clean doesn't seem to work 
:: very well (in my past experience). 
del /s /q "bin.v2\*.*"

:: Just for fun, run clean anyway.
bjam --clean-all

:: We add Add extra c/c++ flags to specify the windows version to Vista, 
:: otherwise it will target XP.

:: First pass of compilation. Compiling all libs as multithreaded DLLS, 
:: optimized for speed, 64 bit arch. 
bjam.exe -a -j%COMPILATION_NUMCORES% --toolset=msvc --layout=system cxxflags="-D_WIN32_WINNT=0x0600" cflags="-D_WIN32_WINNT=0x0600" optimization=speed link=shared threading=multi address-model=64 --stagedir="stage\msvc\Release x64" release stage

:: Set up paths to the bzip and zlib source for the second pass of boost 
:: compilation. 
set BZIP_SRC=%cd%\..\..\bzip2\%BZIP_VERSION%
set ZLIB_SRC=%cd%\..\..\zlib\%ZLIB_VERSION%

:: Second pass, specifically build multithreaded optimized dlls for 
:: iostreams, 64 bit arch. 
bjam.exe -a -j%COMPILATION_NUMCORES% --toolset=msvc --layout=system cxxflags="-D_WIN32_WINNT=0x0600" cflags="-D_WIN32_WINNT=0x0600" optimization=speed link=shared threading=multi address-model=64 --stagedir="stage\msvc\Release x64" --with-iostreams -sNO_COMPRESSION=0 -sNO_ZLIB=0 -sBZIP2_SOURCE=%BZIP_SRC% -sZLIB_SOURCE=%ZLIB_SRC% release stage

:: Clean again before building debug version.
del /s /q "bin.v2\*.*"
bjam --clean-all

:: Third pass of compilation. Compiling all libs as multithreaded DLLS, 
:: debug libs, 64 bit arch.
bjam.exe -a -j%COMPILATION_NUMCORES% --toolset=msvc --layout=system cxxflags="-D_WIN32_WINNT=0x0600" cflags="-D_WIN32_WINNT=0x0600" link=shared threading=multi address-model=64 --stagedir="stage\msvc\Debug x64" debug stage

:: Fourth pass, specifically build multithreaded debug dlls for 
:: iostreams, 64 bit arch. 
bjam.exe -a -j%COMPILATION_NUMCORES% --toolset=msvc --layout=system cxxflags="-D_WIN32_WINNT=0x0600" cflags="-D_WIN32_WINNT=0x0600" link=shared threading=multi address-model=64 --stagedir="stage\msvc\Debug x64" --with-iostreams -sNO_COMPRESSION=0 -sNO_ZLIB=0 -sBZIP2_SOURCE=%BZIP_SRC% -sZLIB_SOURCE=%ZLIB_SRC% debug stage

:: Recursively search for PDB files in debug directory, copy them to 
:: the debug stage directory.
for /R "%cd%\bin.v2\libs\" %%f in (*.pdb) do xcopy /Y %%f "%cd%\stage\msvc\Debug x64\lib\"

:: Change back to the scripts directory.
cd ..\..\..\scripts\win

:: All Done.
exit /B

:: This will print out help information to the console to assist the 
:: user in correctly configuring the script in the event that the variables 
:: were not setup. 
:RequiresSetup
echo. & echo Please edit this batch file to have the following variables set correctly: & echo.
echo 	BOOST_VERSION - Set this to the name of boost root directory, the folder which includes the version number in it. & echo.
echo 	BZIP_VERSION - Set this to the name of the directory containing the bzip2 source code, the name which also includes the version. & echo.
echo 	ZLIB_VERSION - Set this to the name of the directory containing the zlib source code, the name which also includes the version. & echo.
echo. & echo See script comments for more details.
timeout 10
exit /B