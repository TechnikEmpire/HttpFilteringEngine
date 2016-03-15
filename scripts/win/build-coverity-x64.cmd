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

:: Invoke the 64 bit Visual Studio command prompt environment, for 64 
:: bit build tool stuff to be setup. If you have installed VS 2015 to a 
:: non-standard place, or have an older version of VS, you will need to 
:: change this line.
call "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat" amd64

cd "%cd%\..\..\ide\msvc"

cov-build --dir cov-int msbuild libhttpfilteringengine.sln /t:Build /p:Configuration="Release x64";Platform=Win

:: Change back to the scripts directory.
cd ..\..\scripts\win