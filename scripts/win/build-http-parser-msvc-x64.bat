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

:: Set HTTP_PARSER_VERSION to the extracted folder name, which includes 
:: the version. So, as an example, in 
:: HTTP_FILTER_ENGINE_ROOT_DIR\deps\http-parser, you should have extracted 
:: lets say HTTP Parser 2.5.0. So you'll have 
:: HTTP_FILTER_ENGINE_ROOT_DIR\deps\http-parser\http-parser-2.5.0\SOURCES. 
:: Therefore, set HTTP_PARSER_VERSION to "http-parser-2.5.0" like so:
:: HTTP_PARSER_VERSION=http-parser-2.5.0 
set HTTP_PARSER_VERSION=http-parser-2.6.0

:: Make sure the variables have been set.
if [%HTTP_PARSER_VERSION%] == [] GOTO RequiresSetup

:: Invoke the 64 bit Visual Studio command prompt environment, for 64 
:: bit build tool stuff to be setup. If you have installed VS 2015 to a 
:: non-standard place, or have an older version of VS, you will need to 
:: change this line. 
call "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat" amd64

:: Change the current directory to the http_parser source directory.
cd ..\..\deps\http-parser\%HTTP_PARSER_VERSION%

:: Delete all existing build artifacts.
del *.dll
del *.obj
del *.pdb

:: Compile release and link dll by the same name as the single source file.
cl /nologo /D_USRDLL /D_WINDLL /Ox /MD /LD /I %cd% http_parser.c

:: Generate corresponding debug LIB file.
LIB /OUT:http_parser.lib http_parser.obj

:: Generate output directories. If they exist, no harm, no errors.
mkdir "..\msvc"
mkdir "..\msvc\Release x64"
mkdir "..\msvc\Release x64\lib"
mkdir "..\msvc\Debug x64"
mkdir "..\msvc\Debug x64\lib"
mkdir "..\msvc\include"

:: Copy the release build output (dll and lib files), as well as the headers to 
:: the generated output directories. 
xcopy /Y *.dll "..\msvc\Release x64\lib\"
xcopy /Y *.lib "..\msvc\Release x64\lib\"
xcopy /Y *.h "..\msvc\include"

:: Delete all existing build artifacts before building debug.
del *.dll
del *.obj
del *.pdb

:: Compile debug and link dll by the same name as the single source file.
cl /nologo /D_USRDLL /D_WINDLL /DEBUG /Zi /MDd /LD /I %cd% http_parser.c

:: Generate corresponding debug LIB file.
LIB /OUT:http_parser.lib http_parser.obj

:: Copy the debug build output (dll and lib files), as well as the headers to 
:: the generated output directories. 
xcopy /Y *.dll "..\msvc\Debug x64\lib\"
xcopy /Y *.lib "..\msvc\Debug x64\lib\"
xcopy /Y *.pdb "..\msvc\Debug x64\lib\"

:: Change back to the scripts directory.
cd ..\..\..\scripts\win

:: All Done.
exit /B

:: This will print out help information to the console to assist the 
:: user in correctly configuring the script in the event that the variables 
:: were not setup. 
:RequiresSetup
echo. & echo Please edit this batch file to have the following variables set correctly: & echo.
echo 	HTTP_PARSER_VERSION - Set this to the name of the Http Parser source directory, the folder which includes the version number in it. & echo.
echo. & echo See script comments for more details.
timeout 10
exit /B