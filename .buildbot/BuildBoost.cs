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

    /// <summary>
    /// The BuildBoost class handles the task of checking out all boost modules
    /// necessary for the function of HttpFilteringEngine, and then compiling
    /// and staging the output for each supplied configuration and target
    /// architucture.
    /// </summary>
    public class BuildBoost : AbstractBuildTask
    {
        public override Guid GUID
        {
            get
            {
                return Guid.Parse("22762ad9-fff1-4faf-a3ff-0148385d40b9");
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
                // Depends on the SetupSubmodules task.
                return new List<Guid>(new[] {Guid.Parse("01241f94-9a80-42e9-bb23-f1470c40cff6")});
            }
        }

        public override string TaskFriendlyName
        {
            get
            {
                return "Boost Libraries Compilation";
            }
        }

        /// <summary>
        /// Path to the git exectable to use.
        /// </summary>
        private string m_gitDir = string.Empty;

        public BuildBoost(string scriptAbsolutePath) : base(scriptAbsolutePath)
        {

        }

        public override bool Clean()
        {
            // Clear errors before trying.
            Errors.Clear();

            // XXX TODO. Just run b2 --clean but it's not really necessary because
            // we use the -a switch always, which forces rebuild of all.
            return true;
        }

        public override bool Run(BuildConfiguration config, Architecture arch)
        {
            if (!ConfigureTools())
            {
                Errors.Add(new Exception("Failed to discover and or download git for boost modular build."));
                return false;
            }

            // Build out the base path to zlib.
            StringBuilder zlibBasePath = new StringBuilder(WorkingDirectory);
            zlibBasePath.Append(Path.DirectorySeparatorChar);
            zlibBasePath.Append("deps");
            zlibBasePath.Append(Path.DirectorySeparatorChar);
            zlibBasePath.Append("zlib");

            // Build out the base path to bzip2.
            StringBuilder bzip2BasePath = new StringBuilder(WorkingDirectory);
            bzip2BasePath.Append(Path.DirectorySeparatorChar);
            bzip2BasePath.Append("deps");
            bzip2BasePath.Append(Path.DirectorySeparatorChar);
            bzip2BasePath.Append("bzip2");

            // Build out the base path to the boost source directory.
            StringBuilder boostBasePath = new StringBuilder(WorkingDirectory);
            boostBasePath.Append(Path.DirectorySeparatorChar);
            boostBasePath.Append("deps");
            boostBasePath.Append(Path.DirectorySeparatorChar);
            boostBasePath.Append("boost");

            var boostWorkingDirectory = boostBasePath.ToString().ConvertToHostOsPath();
            
            if (!InitializeSubmodules(boostWorkingDirectory))
            {
                Errors.Add(new Exception("Failed to initialize boost submodules."));
                return false;
            }            

            if (!InitializeBoostBuild(boostWorkingDirectory))
            {
                Errors.Add(new Exception("Failed to initialize boost build engine."));
                return false;
            }
            
            // Do build for each config + arch.
            foreach (BuildConfiguration cfg in Enum.GetValues(typeof(BuildConfiguration)))
            {
                if (config.HasFlag(cfg))
                {
                    foreach (Architecture a in Enum.GetValues(typeof(Architecture)))
                    {
                        if (arch.HasFlag(a))
                        {
                            var firstPassBuildArgs = new List<string>();
                            firstPassBuildArgs.Add("-a");
                            firstPassBuildArgs.Add(string.Format("-j{0}", Environment.ProcessorCount));
                            firstPassBuildArgs.Add("--toolset=msvc");
                            firstPassBuildArgs.Add("--layout=system");
                            firstPassBuildArgs.Add("cxxflags=\"-D_WIN32_WINNT=0x0600\"");
                            firstPassBuildArgs.Add("cflags=\"-D_WIN32_WINNT=0x0600\"");
                            firstPassBuildArgs.Add("link=shared");
                            firstPassBuildArgs.Add("threading=multi");
                            
                            switch(a)
                            {
                                case Architecture.x86:
                                {
                                    firstPassBuildArgs.Add("address-model=32");
                                }
                                break;

                                case Architecture.x64:
                                {
                                    firstPassBuildArgs.Add("address-model=64");
                                }
                                break;
                            }

                            firstPassBuildArgs.Add("--stagedir=\"stage" + Path.DirectorySeparatorChar + "msvc" + Path.DirectorySeparatorChar + String.Format("{0} {1}", cfg.ToString(), a.ToString()) + "\"");
                            
                            var secondPassArgs = new List<string>(firstPassBuildArgs);

                            // Add debug/release to args.
                            firstPassBuildArgs.Add(cfg.ToString().ToLower());

                            firstPassBuildArgs.Add("stage");

                            WriteLineToConsole(string.Join(" ", firstPassBuildArgs));

                            secondPassArgs.Add("--with-iostreams");
                            secondPassArgs.Add("-sNO_COMPRESSION=0");
                            secondPassArgs.Add("-sNO_ZLIB=0");                            
                            secondPassArgs.Add(string.Format("-sBZIP2_SOURCE={0}", bzip2BasePath.ToString()));
                            secondPassArgs.Add(string.Format("-sZLIB_SOURCE={0}", zlibBasePath.ToString()));                            

                            // Add debug/release to args.
                            secondPassArgs.Add(cfg.ToString().ToLower());

                            secondPassArgs.Add("stage");

                            var b2Path = boostWorkingDirectory + Path.DirectorySeparatorChar + "b2.exe";

                            if(RunProcess(boostWorkingDirectory, b2Path, firstPassBuildArgs) != 0)
                            {
                                Errors.Add(new Exception(string.Format("Failed first pass build of boost for configuration {0} and arch {1}.", cfg.ToString(), a.ToString())));
                                return false;
                            }

                            if(RunProcess(boostWorkingDirectory, b2Path, secondPassArgs) != 0)
                            {
                                Errors.Add(new Exception(string.Format("Failed second pass build of boost for configuration {0} and arch {1}.", cfg.ToString(), a.ToString())));
                                return false;
                            }
                        }
                    }
                }
            }

            return true;
        }

        private bool InitializeBoostBuild(string boostBasePath)
        {
            // Call bootstrap with default params. Defaults to msvc.
            
            bool needsBuilt = true;

            var b2Path = boostBasePath + Path.DirectorySeparatorChar + "b2.exe";

            if (File.Exists(boostBasePath + Path.DirectorySeparatorChar + "b2.exe"))
            {
                WriteLineToConsole("Boost build engine already built. Skipping build of boost engine.");
                needsBuilt = false;
            }

            if(needsBuilt)
            {
                var retCode = RunProcess(boostBasePath, "cmd.exe", new List<string>(new[] { "call /C bootstrap.bat" }));

                if(retCode != 0)
                {
                    Errors.Add(new Exception("Failed to build boost build engine."));
                    return false;
                }
            }
            
            // Force building of headers. Must be done to configure headers/paths
            // in modular boost properly.
            var headersRetCode = RunProcess(boostBasePath, b2Path, new List<string>(new[] {"-a headers"}));

            return headersRetCode == 0;
        }

        private bool InitializeSubmodules(string boostBasePath)
        {
            // All of these args are used to checkout only what is absolutely
            // required from modular boost for the HttpFilteringEngine project
            // to function correctly.
            var boostGitCheckoutArgs = new List<string>();
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "system");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "config");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "iostreams");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "date_time");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "core");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "exception");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "throw_exception");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "detail");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "assert");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "static_assert");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "type_traits");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "integer");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "smart_ptr");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "predef");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "mpl");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "preprocessor");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "range");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "iterator");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "concept_check");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "utility");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "lexical_cast");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "numeric");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "array");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "functional");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "function");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "type_index");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "container");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "move");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "intrusive");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "math");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "bind");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "thread");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "regex");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "tokenizer");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "asio");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "align");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "tuple");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "chrono");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "ratio");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "io");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "optional");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "winapi");
            boostGitCheckoutArgs.Add("libs" + Path.DirectorySeparatorChar + "algorithm");
            boostGitCheckoutArgs.Add("." + Path.DirectorySeparatorChar + "tools" + Path.DirectorySeparatorChar + "build");
            boostGitCheckoutArgs.Add("." + Path.DirectorySeparatorChar + "tools" + Path.DirectorySeparatorChar + "inspect");

            var fullGitPath = m_gitDir + Path.DirectorySeparatorChar + "git.exe";

            var checkoutAttempts = 0;
            var successfulCheckouts = 0;
            foreach (var checkoutCommand in boostGitCheckoutArgs)
            {
                ++checkoutAttempts;

                WriteLineToConsole(string.Format("Initializing submodule {0} ...", checkoutCommand));

                if (RunProcess(boostBasePath, fullGitPath, new List<string>(new[] { "submodule update --init " + checkoutCommand })) == 0)
                {
                    ++successfulCheckouts;
                    WriteLineToConsole(string.Format("Submodule {0} successfully initialized.", checkoutCommand));
                }
                else
                {
                    WriteLineToConsole(string.Format("Failed to initialize submodule {0}.", checkoutCommand));
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

                if (!VerifyFileHash(HashAlgorithmName.SHA1, fullZipPath, portableGitSha256))
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