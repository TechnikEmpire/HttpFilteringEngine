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

    public class SetupSubmodules : AbstractBuildTask
    {
        public override Guid GUID
        {
            get
            {
                return Guid.Parse("01241f94-9a80-42e9-bb23-f1470c40cff6");
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
                return "Git Submodule Setup";
            }
        }

        /// <summary>
        /// Path to the git exectable to use.
        /// </summary>
        private string m_gitDir = string.Empty;

        public SetupSubmodules(string scriptAbsolutePath) : base(scriptAbsolutePath)
        {

        }

        public override bool Clean()
        {
            Errors.Clear();

            try
            {
                // Delete deps directory.
                var depsDir = WorkingDirectory + Path.DirectorySeparatorChar + "deps";
                if (Directory.Exists(depsDir))
                {
                    Directory.Delete(depsDir, true);
                }
            }
            catch (Exception e)
            {
                Errors.Add(e);
                return false;
            }

            // Force reset all submodules.
            if (!ConfigureTools())
            {
                Errors.Add(new Exception("Failed to discover and or download git for boost modular build."));
                return false;
            }

            var fullGitPath = m_gitDir + Path.DirectorySeparatorChar + "git.exe";

            if (RunProcess(WorkingDirectory, fullGitPath, new List<string>(new[] { "submodule update --init" })) == 0)
            {
                return true;
            }

            return false;
        }

        public override bool Run(BuildConfiguration config, Architecture arch)
        {
            // All we're gonna do here is make sure we've got all of our submodules
            // present and ready to go.

            if (!ConfigureTools())
            {
                Errors.Add(new Exception("Failed to discover and or download git."));
                return false;
            }

            // Build out the base path to our submodules.
            StringBuilder submoduleBasePath = new StringBuilder(WorkingDirectory);
            submoduleBasePath.Append(Path.DirectorySeparatorChar);
            submoduleBasePath.Append("deps");

			var fullGitPath = m_gitDir + Path.DirectorySeparatorChar + "git.exe";
			
			WriteLineToConsole("Initializing submodules ...");

            if (RunProcess(WorkingDirectory, fullGitPath, new List<string>(new[] { "submodule update --init"})) != 0)
            {				
				WriteLineToConsole("Failed to initialize submodules."); 
				return false;
            }
			
            var submoduleDirs = Directory.GetDirectories(submoduleBasePath.ToString(), "*.*", SearchOption.TopDirectoryOnly);

            var checkoutAttempts = 0;
            var successfulCheckouts = 0;            

			// Now we do recursive init on each submodule, except boost.
            foreach (var submodulePath in submoduleDirs)
            {
                ++checkoutAttempts;

                var dirInfo = new DirectoryInfo(submodulePath);

                string checkoutCommand = string.Empty;
                string submoduleIdentifier = "deps" + Path.DirectorySeparatorChar + dirInfo.Name;

                // We want to recursively init everything EXCEPT boost.
                if (!dirInfo.Name.Equals("boost", StringComparison.OrdinalIgnoreCase))
                {
                    checkoutCommand += "--recursive";
                }

                checkoutCommand += " " + submoduleIdentifier;

                WriteLineToConsole(string.Format("Initializing submodule {0} ...", submoduleIdentifier));

                if (RunProcess(WorkingDirectory, fullGitPath, new List<string>(new[] { "submodule update --init " + checkoutCommand })) == 0)
                {
                    ++successfulCheckouts;
                    WriteLineToConsole(string.Format("Submodule {0} successfully initialized.", submoduleIdentifier));
                }
                else
                {
                    WriteLineToConsole(string.Format("Failed to initialize submodule {0}.", submoduleIdentifier));
                }
            }

            return checkoutAttempts > 0 && successfulCheckouts == checkoutAttempts;
        }

        private bool ConfigureTools()
        {
            m_gitDir = ConfigureGit();

            if (string.IsNullOrEmpty(m_gitDir) || string.IsNullOrWhiteSpace(m_gitDir))
            {
                // Failed to find git.
                return false;
            }

            return true;
        }

        /// <summary>
        /// Ensures that we have git available to us for the build process. If
        /// git cannot be found in any environmental variable, then we'll fetch
        /// a portable copy.
        /// </summary>
        /// <returns>
        /// The full path to the parent directory of the git primary executable.
        /// </returns>
        private string ConfigureGit()
        {
            WriteLineToConsole("Searching for existing git installations...");

            var envVars = Environment.GetEnvironmentVariables();

            foreach (var variable in envVars.Keys)
            {
                var split = ((string)envVars[variable]).Split(Path.PathSeparator);

                foreach (var val in split)
                {
                    if (Directory.Exists(val))
                    {
                        string gitPath = val.ConvertToHostOsPath() + Path.DirectorySeparatorChar + "git.exe";

                        if (File.Exists(gitPath))
                        {
                            return Directory.GetParent(gitPath).FullName.ConvertToHostOsPath();
                        }
                    }
                }
            }

            // Means we didn't find git.
            var toolsPath = WorkingDirectory + Path.DirectorySeparatorChar + "tools";
            string portableGitDownloadUri = string.Empty;
            string portableGitSha256 = string.Empty;


            if (System.Runtime.InteropServices.RuntimeInformation.OSArchitecture.HasFlag(System.Runtime.InteropServices.Architecture.X64))
            {
                portableGitDownloadUri = @"https://github.com/git-for-windows/git/releases/download/v2.10.0.windows.1/MinGit-2.10.0-64-bit.zip";
                portableGitSha256 = @"2e1101ec57da526728704c04792293613f3c5aa18e65f13a4129d00b54de2087";
            }
            else
            {
                portableGitDownloadUri = @"https://github.com/git-for-windows/git/releases/download/v2.10.0.windows.1/MinGit-2.10.0-32-bit.zip";
                portableGitSha256 = @"36f890870126dcf840d87eaec7e55b8a483bc336ebf8970de2f9d549a3cfc195";
            }

            var portableGitZipName = "PortableGit.zip";

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
            var decompressedPath = toolsPath + Path.DirectorySeparatorChar + "portablegit";

            string[] existingGitPaths = new string[0];

            if (Directory.Exists(decompressedPath))
            {
                existingGitPaths = Directory.GetFiles(decompressedPath, "git.exe", SearchOption.AllDirectories);

                if (existingGitPaths.Length > 0)
                {
                    return Directory.GetParent(existingGitPaths[0]).FullName.ConvertToHostOsPath();
                }
            }

            // If we reached here, then we need to decompress.
            DecompressArchive(fullZipPath, decompressedPath);

            existingGitPaths = Directory.GetFiles(decompressedPath, "git.exe", SearchOption.AllDirectories);

            if (existingGitPaths.Length == 0)
            {
                WriteLineToConsole("Failed to find git executable in extracted package.");
                return string.Empty;
            }

            return Directory.GetParent(existingGitPaths[0]).FullName.ConvertToHostOsPath();
        }
    }
}