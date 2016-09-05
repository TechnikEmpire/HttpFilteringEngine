/*
* Copyright (c) 2016 Jesse Nicholson.
*
* This file is part of Http Filtering Engine.
*
* Http Filtering Engine is free software: you can redistribute it and/or
* modify it under the terms of the GNU General Public License as published
* by the Free Software Foundation, either version 3 of the License, or (at
* your option) any later version.
*
* In addition, as a special exception, the copyright holders give
* permission to link the code of portions of this program with the OpenSSL
* library.
*
* You must obey the GNU General Public License in all respects for all of
* the code used other than OpenSSL. If you modify file(s) with this
* exception, you may extend this exception to your version of the file(s),
* but you are not obligated to do so. If you do not wish to do so, delete
* this exception statement from your version. If you delete this exception
* statement from all source files in the program, then also delete it
* here.
*
* Http Filtering Engine is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
* Public License for more details.
*
* You should have received a copy of the GNU General Public License along
* with Http Filtering Engine. If not, see <http://www.gnu.org/licenses/>.
*/

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using BuildBot.Extensions;
using BuildBot.Net.Http.Handlers;
using BuildBotCore;
using System.Security.Cryptography;
using BuildBotCore.Common.ExternalTools.Compilers;
using static BuildBotCore.Common.ExternalTools.Compilers.MSVCCompilerTask;
using System.Threading;

namespace HttpFilteringEngine
{

    public class SetupWinDivert : AbstractBuildTask
    {
        public override Guid GUID
        {
            get
            {
                return Guid.Parse("dce82bd6-da9e-49c8-991a-b3383b156a43");
            }
        }

        public override string Help
        {
            get
            {
                // XXX TODO - We're not very helpful. But, what help can we
                // offer? This is straight forward. and we're entirely in
                // control of this simple process.
                return "No help to offer.";
            }
        }

        public override bool IsOsPlatformSupported
        {
            get
            {
                // XXX TODO - Update when other operating systems are supported.
                bool isWindows = System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows);
                return isWindows;
            }
        }

        public override Architecture SupportedArchitectures
        {
            get
            {
                return Architecture.x64 | Architecture.x86;
            }
        }

        public override List<Guid> TaskDependencies
        {
            get
            {
                // Depends on nothing.
                return new List<Guid>();
            }
        }

        public override string TaskFriendlyName
        {
            get
            {
                return "WinDivert Driver Setup";
            }
        }

        /// <summary>
        /// Path to the git exectable to use.
        /// </summary>
        private string m_gitDir = string.Empty;

        public SetupWinDivert(string scriptAbsolutePath) : base(scriptAbsolutePath)
        {

        }

        public override bool Clean()
        {
            try
            {
                var winDivertDir = WorkingDirectory + Path.DirectorySeparatorChar + "deps" + Path.DirectorySeparatorChar + "windivert";

                if(Directory.Exists(winDivertDir))
                {
                    Directory.Delete(winDivertDir, true);
                }
            }   
            catch(Exception e)
            {
                Errors.Add(e);                
                return false;
            }

            return true;
        }

        public override bool Run(BuildConfiguration config, Architecture arch)
        {
            // Means we didn't find git.
            var toolsPath = WorkingDirectory + Path.DirectorySeparatorChar + "tools";
            string portableGitDownloadUri = string.Empty;
            string portableGitSha256 = string.Empty;

            portableGitDownloadUri = @"https://github.com/basil00/Divert/releases/download/v1.2.0-rc/WinDivert-1.2.0-rc-MSVC.zip";
            portableGitSha256 = @"7A194D5066C4093A370E3EA474371A4CF9976D28763C253D9DDF312BC2B33715";

            var portableGitZipName = "WinDivert.zip";

            var fullZipPath = toolsPath + Path.DirectorySeparatorChar + portableGitZipName;

            bool zipAlreadyExists = File.Exists(fullZipPath);

            if (zipAlreadyExists)
            {
                WriteLineToConsole("Discovered previous download. Verifying integrity.");

                // Just let it revert to false if hash doesn't match. The file
                // would simply be overwritten.
                zipAlreadyExists = VerifyFileHash(HashAlgorithmName.SHA256, fullZipPath, portableGitSha256);

                if (!zipAlreadyExists)
                {
                    WriteLineToConsole("Integrity check failed. Attempting clean download.");
                }
                else
                {
                    WriteLineToConsole("Integrity check passed. Using cached download.");
                }
            }

            if (!zipAlreadyExists)
            {
                var downloadTask = DownloadFile(portableGitDownloadUri, toolsPath, null, portableGitZipName);
                downloadTask.Wait();

                if (!VerifyFileHash(HashAlgorithmName.SHA256, fullZipPath, portableGitSha256))
                {
                    throw new Exception("Downloaded file does not match expected hash.");
                }
            }

            // Before decompressing again, let's see if we can find an already
            // decompressed perl.exe.
            var decompressedPath = WorkingDirectory + Path.DirectorySeparatorChar + "deps" + Path.DirectorySeparatorChar + "windivert" + Path.DirectorySeparatorChar + "msvc";

            string[] existingGitPaths = new string[0];

            if (Directory.Exists(decompressedPath))
            {
                existingGitPaths = Directory.GetFiles(decompressedPath, "WinDivert.dll", SearchOption.AllDirectories);

                if (existingGitPaths.Length > 0)
                {
                    return true;
                }
            }

            // If we reached here, then we need to decompress.
            DecompressArchive(fullZipPath, decompressedPath);

            // Collapse the top directory which contains version 
            // info and rename the 64 bit folder from amd64 to x64.
            var amd64Path = Directory.GetDirectories(decompressedPath, "amd64", SearchOption.AllDirectories);

            if(amd64Path.Length != 1)
            {
                WriteLineToConsole("Failed to find WinDivert 64 bit library in extracted package.");
                return false;
            }

            var parentDir = Directory.GetParent(amd64Path[0]);

            var allDirs = Directory.GetDirectories(parentDir.FullName, "*.*", SearchOption.TopDirectoryOnly);

            foreach(var dir in allDirs)
            {
                var dirInfo = new DirectoryInfo(dir);
                if(dirInfo.Name.Equals("amd64", StringComparison.OrdinalIgnoreCase))
                {
                    Directory.Move(dir, decompressedPath + Path.DirectorySeparatorChar + "x64");
                }
                else
                {
                    Directory.Move(dir, decompressedPath + Path.DirectorySeparatorChar + dirInfo.Name);
                }
            }

            // Delete the now empty, version specific folder.
            Directory.Delete(parentDir.FullName, true);

            existingGitPaths = Directory.GetFiles(decompressedPath, "WinDivert.dll", SearchOption.AllDirectories);

            if (existingGitPaths.Length == 0)
            {
                WriteLineToConsole("Failed to find WinDivert library in extracted package.");
                return false;
            }

            return true;
        
        }        
    }
}