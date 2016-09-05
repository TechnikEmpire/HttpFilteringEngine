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
    /// The BuildOpenSSL class handles compilation of OpenSSL for both x86 and
    /// x64 arch targets. This class will download the required tools, namely
    /// perl and nasm if such tools are not found in any existing environment
    /// variable. This class, or rather build task, will ensure that openSSL is
    /// configured, compiled and staged correctly provided that the user has
    /// Visual Studio 2015 installed with C/C++ support. All other requirements
    /// and configuration are handled herin.
    /// </summary>
    public class BuildOpenSSL : AbstractBuildTask
    {
        public override Guid GUID
        {
            get
            {
                return Guid.Parse("54917d60-831b-480b-b63e-e3a4f3c17994");
            }
        }

        public override string Help
        {
            get
            {
                StringBuilder help = new StringBuilder();
                help.AppendLine("In the event of an error, especially a \"previously failed configuration\" error, delete the openSSL submodule directory and re-initialize the submodule.");
                help.AppendLine("This can be done with \"git submodule update --init PATH\\TO\\OPENSSL\\SUBMODULE");
                return help.ToString();
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
                return "OpenSSL Compilation";
            }
        }

        public BuildOpenSSL(string scriptAbsolutePath) : base(scriptAbsolutePath)
        {

        }

        public override bool Clean()
        {
            // Clear errors before trying.
            Errors.Clear();

            // XXX TODO - Need to build out the same paths as Run(),
            // get MSVC tools environment and then run nmake clean on
            // both the x86 and x64 dirs. Then, delete the output "MSVC"
            // folder.

            // Just return true for now. No harm.
            return true;
        }

        // Holds the path to the x86 source dir for openSSL.
        private string m_openSslx86Dir = string.Empty;

        // Holds the path to the x64 source dir for openSSL.
        private string m_openSslx64Dir = string.Empty;

        // Holds the path to the discovered or extracted NASM.exe.
        private string m_nasmDir = string.Empty;

        // Holds the path to the discovered or extracted PERL.exe.
        private string m_perlDir = string.Empty;

        public override bool Run(BuildConfiguration config, Architecture arch)
        {
            // Clear errors before trying.
            Errors.Clear();

            if (!SupportedArchitectures.HasFlag(arch))
            {
                Errors.Add(new Exception("Unsupported architecture specified for build task."));
                return false;
            }

            if (!ConfigureDirectories())
            {
                Errors.Add(new Exception("Failed to configure arch specific directories for openSSL build."));
                return false;
            }

            // We need to get the environment for a the MSVC compiler and
            // associated build tools.
            var installedMsvcVersions = MSVCCompilerTask.InstalledToolVersions;

            if (installedMsvcVersions.Count == 0)
            {
                Errors.Add(new Exception("Could not detect a compatible installation of MSVC."));
                return false;
            }

            // Get a reversed list of tool versions and iterate over them, until we find
            // an installed version. This way we're always working with the latest
            // version available.
            var allVersions = Enum.GetValues(typeof(ToolVersions)).Cast<ToolVersions>().Reverse();

            ToolVersions versionToUse = ToolVersions.v11;

            foreach (var msvcVersion in allVersions)
            {
                if (installedMsvcVersions.ContainsKey(msvcVersion))
                {
                    versionToUse = msvcVersion;
                    WriteLineToConsole(string.Format("Discovered and using MSVC {0} for compilation.", versionToUse.ToString()));
                    break;
                }
            }

            // Build out the base path to the openSSL source directory.
            StringBuilder opensslBasePath = new StringBuilder(WorkingDirectory);
            opensslBasePath.Append(Path.DirectorySeparatorChar);
            opensslBasePath.Append("deps");
            opensslBasePath.Append(Path.DirectorySeparatorChar);
            opensslBasePath.Append("openssl");

            int numCompilationAttempts = 0;
            int numSuccessfulCompilations = 0;

            // We're only going to iterate over arches. We're not going to build a debug
            // version of openSSL, just release versions for each arch.
            foreach (Architecture a in Enum.GetValues(typeof(Architecture)))
            {
                if (arch.HasFlag(a))
                {
                    ++numCompilationAttempts;

                    var finalBuildEnvironment = MSVCCompilerTask.GetEnvironmentForVersion(versionToUse, a);

                    // Add perl path if it doesn't already exist.
                    if (finalBuildEnvironment["PATH"].IndexOf(m_perlDir) == -1)
                    {
                        finalBuildEnvironment["PATH"] += (Path.PathSeparator + m_perlDir);
                    }

                    var configArgs = new List<string>();

                    configArgs.Add("no-idea");
                    configArgs.Add("no-mdc2");
                    configArgs.Add("no-rc5");
                    configArgs.Add("no-comp");

                    // XXX TODO - Remove this option when upgrading to openSSL 1.1.0
                    configArgs.Add("no-ssl2");

                    configArgs.Add("no-ssl3");
                    configArgs.Add("no-weak-ssl-ciphers");
                    configArgs.Add("threads");

                    // The working dir. This will either be the x86 or x64 openSSL source dir.
                    string workingDirectory = string.Empty;

                    // We need to include nasm regardless of rater arch because
                    // the openSSL configuration system will whine and quit if
                    // we don't. We should be guaranteed to have a PATH variable
                    // here unless something went horribly wrong.
                    finalBuildEnvironment["PATH"] += (Path.PathSeparator + m_nasmDir);

                    // XXX TODO - This needs to go away when we bump to OpenSSL 1.1.0
                    string whichAsmCall = string.Empty;

                    string openSslInstallDir = string.Empty;

                    switch (a)
                    {
                        case Architecture.x86:
                            {

                                // Build inside the x86 dir
                                workingDirectory = m_openSslx86Dir;

                                // Set x86 release build.
                                configArgs.Insert(0, "VC-WIN32");

                                whichAsmCall = "ms" + Path.DirectorySeparatorChar + "do_nasm.bat";

                                openSslInstallDir = opensslBasePath.ToString().ConvertToHostOsPath() +
                                            Path.DirectorySeparatorChar +
                                            "msvc" +
                                            Path.DirectorySeparatorChar +
                                            "Releasex86";
                            }
                            break;

                        case Architecture.x64:
                            {
                                // Build inside the x64 dir
                                workingDirectory = m_openSslx64Dir;

                                whichAsmCall = "ms" + Path.DirectorySeparatorChar + "do_win64a.bat";

                                // Set x64 release build.
                                configArgs.Insert(0, "VC-WIN64A");

                                openSslInstallDir = opensslBasePath.ToString().ConvertToHostOsPath() +
                                            Path.DirectorySeparatorChar +
                                            "msvc" +
                                            Path.DirectorySeparatorChar +
                                            "Releasex64";                                
                            }
                            break;

                        default:
                            {
                                WriteLineToConsole(string.Format("Dont have arch: {0}", a.ToString()));
                                continue;
                            }
                    }

                    // Setup prefix (output) path to deps/openssl/msvc/ReleaseX64
                                configArgs.Add(
                                    string.Format(
                                        "--prefix={0}",
                                       openSslInstallDir)
                                            );

                                // Setup config path to deps/openssl/msvc/ReleaseX86
                                configArgs.Add(
                                    string.Format(
                                        "--openssldir={0}",
                                        openSslInstallDir)
                                            );


                    WriteLineToConsole(string.Format("Configuring for arch: {0}", a.ToString()));

                    WriteLineToConsole(workingDirectory);

                    WriteLineToConsole(string.Format("Config Path: {0}", workingDirectory + Path.DirectorySeparatorChar + "Configure"));

                    // Push configure script to front of args.
                    configArgs.Insert(0, "Configure");

                    WriteLineToConsole(string.Join(" ", configArgs));

                    // Run the configuration process.
                    var perlExitCode = RunProcess(workingDirectory, m_perlDir + Path.DirectorySeparatorChar + "perl.exe", configArgs, Timeout.Infinite, finalBuildEnvironment);

                    // Now run the actual build process.

                    // Example of the call string expanded/populated:
                    // call "ms\do_nasm.bat" && nmake -f ms\ntdll.mak && nmake -f ms\ntdll.mak install
                    
                    string callArgs = string.Format("/C \"{0}\" && {1} && {2}", whichAsmCall, "nmake -f ms" + Path.DirectorySeparatorChar + "ntdll.mak", "nmake -f ms" + Path.DirectorySeparatorChar + "ntdll.mak install");

                    // XXX TODO - This is way to do it when we jump up to OpenSSL 1.1.0
                    //string callArgs = string.Format("/C {0} && {1}", "nmake", "nmake install");

                    // Running cmd.exe with these batch commands will build openSSL.
                    var buildExitCode = RunProcess(workingDirectory, "cmd.exe", new List<string> { callArgs }, Timeout.Infinite, finalBuildEnvironment);

                    if(perlExitCode == 0 && buildExitCode == 0)
                    {
                        // Was a success. Move the output folder now.
                        var destBaseDir = opensslBasePath.ToString().ConvertToHostOsPath() +
                                            Path.DirectorySeparatorChar +
                                            "msvc" +
                                            Path.DirectorySeparatorChar;

                        var destReleaseDir = destBaseDir + string.Format("{0} {1}", BuildConfiguration.Release.ToString(), a.ToString());
                        var destDebugDir = destBaseDir + string.Format("{0} {1}", BuildConfiguration.Debug.ToString(), a.ToString());

                        // If we don't delete old stuff, Directory.Move will fail.
                        if(Directory.Exists(destReleaseDir))
                        {
                            Directory.Delete(destReleaseDir, true);
                        }

                        // Move aka rename the directory to have a space.
                        Directory.Move(openSslInstallDir, destReleaseDir);
                        
                        // Simply copy the release folder for arch to a debug folder.
                        CopyDirectory(destReleaseDir, destDebugDir, true);

                        ++numSuccessfulCompilations;
                    }
                }
            }

            var wasSuccess = numCompilationAttempts > 0 && numCompilationAttempts == numSuccessfulCompilations;

            return wasSuccess;
        }

        /// <summary>
        /// Ensures that arch-specific copies of the original source code are
        /// made and staged.
        /// </summary>
        /// <returns>
        /// True if the configuration was previously done or it was performed
        /// with success in this run. False otherwise. Failure is considered
        /// when an exception in this process has been raised and handled
        /// internally.
        /// </returns>
        private bool ConfigureDirectories()
        {
            try
            {
                // Build out the base path to the openSSL source directory.
                StringBuilder opensslBasePath = new StringBuilder(WorkingDirectory);
                opensslBasePath.Append(Path.DirectorySeparatorChar);
                opensslBasePath.Append("deps");
                opensslBasePath.Append(Path.DirectorySeparatorChar);
                opensslBasePath.Append("openssl");

                // Build out the x86 path. If this doesn't exist, then we have not yet
                // set up the two source copies. We need to move the source into a new
                // folder and clone it. The two folders will hold the openSSL source
                // configured for x86 and x64. Configuration modifies the source to the
                // point that separate compilation sources are necessary.
                m_openSslx86Dir = opensslBasePath.ToString() + Path.DirectorySeparatorChar + Architecture.x86.ToString();

                m_openSslx64Dir = opensslBasePath.ToString() + Path.DirectorySeparatorChar + Architecture.x64.ToString();

                if (!Directory.Exists(m_openSslx86Dir))
                {
                    // Start off by moving all the original source files to a new
                    // directory titled "x86".
                    Directory.CreateDirectory(m_openSslx86Dir);
                    DirectoryInfo dirInfo = new DirectoryInfo(m_openSslx86Dir);

                    List<String> openSslSourceFiles = Directory.GetFiles(opensslBasePath.ToString(), "*.*", SearchOption.AllDirectories).ToList();

                    // Get the length of the base path. We'll cut this many
                    // chars off to generate the new, moved base path.
                    var basePathLength = opensslBasePath.ToString().Length;

                    foreach (string file in openSslSourceFiles)
                    {
                        // Recreate the same path except based in our x86 directory.
                        string newPath = dirInfo.FullName + Path.DirectorySeparatorChar + file.Substring(basePathLength);
                        newPath = newPath.ConvertToHostOsPath();

                        // Ensure parent directory in new path exists.
                        var parentDir = Directory.GetParent(newPath);
                        if (!Directory.Exists(parentDir.FullName))
                        {
                            parentDir.Create();
                        }

                        FileInfo mFile = new FileInfo(file);

                        if (new FileInfo(newPath).Exists == false)
                        {
                            mFile.MoveTo(newPath);
                        }
                    }

                    // Now that the sources have been moved to "x86", we need to clone this into
                    // a new folder called "x64".
                    CopyDirectory(m_openSslx86Dir, m_openSslx64Dir, true);

                    // Now delete all the empty directories that the file
                    // moving left behind.
                    var topLevelDirectories = Directory.GetDirectories(opensslBasePath.ToString(), "*.*", SearchOption.TopDirectoryOnly);
                    foreach (var dir in topLevelDirectories)
                    {
                        if (Directory.GetFiles(dir, "*.*", SearchOption.AllDirectories).Length == 0)
                        {
                            Directory.Delete(dir, true);
                        }
                    }
                }
                else
                {
                    // If this was done successfully before, then there ought to only be
                    // two directories in our base openSSL directory. We specifically exclude directories
                    // that have "msvc" in them, to not count the output directory for previously
                    // successful builds.
                    List<String> openSslFolders = Directory.GetDirectories(opensslBasePath.ToString(), "*.*", SearchOption.TopDirectoryOnly).Where(file => !file.Contains("msvc")).ToList();

                    bool foundx86Dir = false;
                    bool foundx64Dir = false;
                    bool foundx86Files = false;
                    bool foundx64Files = false;

                    foreach (var listing in openSslFolders)
                    {
                        FileAttributes attr = File.GetAttributes(listing);

                        if (attr.HasFlag(FileAttributes.Directory))
                        {
                            var dirInfo = new DirectoryInfo(listing);

                            if (dirInfo.Name.Equals(Architecture.x86.ToString(), StringComparison.OrdinalIgnoreCase))
                            {
                                foundx86Dir = true;

                                // Ensure that we have files in this directory.
                                foundx86Files = Directory.GetFiles(dirInfo.FullName, "*.*", SearchOption.AllDirectories).Length > 0;
                            }
                            else if (dirInfo.Name.Equals(Architecture.x64.ToString(), StringComparison.OrdinalIgnoreCase))
                            {
                                foundx64Dir = true;

                                // Ensure that we have files in this directory.
                                foundx64Files = Directory.GetFiles(dirInfo.FullName, "*.*", SearchOption.AllDirectories).Length > 0;
                            }
                        }
                    }

                    // Should have found both directories and they should have been the
                    // only listings.
                    bool previouslySucceeded = foundx86Dir && foundx64Dir && foundx86Files && foundx64Files && openSslFolders.Count == 2;

                    if (!previouslySucceeded)
                    {
                        Errors.Add(new Exception("Possible previously failed or partial configuration detected."));

                        return false;
                    }
                }
            }
            catch (Exception e)
            {
                // Something went wrong. Return false.
                Errors.Add(e);
                if (e.InnerException != null)
                {
                    Errors.Add(e.InnerException);
                }
                return false;
            }

            // Configure perl.
            m_perlDir = ConfigurePerl();

            if (string.IsNullOrEmpty(m_perlDir) || string.IsNullOrWhiteSpace(m_perlDir))
            {
                // Failed to find perl.
                return false;
            }

            // Configure nasm.
            m_nasmDir = ConfigureNasm();

            if (string.IsNullOrEmpty(m_nasmDir) || string.IsNullOrWhiteSpace(m_nasmDir))
            {
                // Failed to find perl.
                return false;
            }

            WriteLineToConsole(m_perlDir);
            WriteLineToConsole(m_nasmDir);

            // As long as no exceptions were caught, we should be good.
            return true;
        }

        /// <summary>
        /// Ensures that we have perl available to us for the build process. If
        /// perl cannot be found in any environmental variable, then we'll fetch
        /// a portable copy.
        /// </summary>
        /// <returns>
        /// The full path to the parent directory of the perl primary executable.
        /// </returns>
        private string ConfigurePerl()
        {

            WriteLineToConsole("Searching for existing perl installations...");

            var envVars = Environment.GetEnvironmentVariables();

            foreach (var variable in envVars.Keys)
            {
                var split = ((string)envVars[variable]).Split(Path.PathSeparator);

                foreach (var val in split)
                {
                    if (Directory.Exists(val))
                    {
                        string perlPath = val.ConvertToHostOsPath() + Path.DirectorySeparatorChar + "perl.exe";

                        if (File.Exists(perlPath))
                        {
                            return Directory.GetParent(perlPath).FullName.ConvertToHostOsPath();
                        }
                    }
                }
            }

            // Means we didn't find perl.

            var toolsPath = WorkingDirectory + Path.DirectorySeparatorChar + "tools";
            string strawberryPerlDownloadUri = string.Empty;
            string strawberryPerlSha1 = string.Empty;


            if (System.Runtime.InteropServices.RuntimeInformation.OSArchitecture.HasFlag(System.Runtime.InteropServices.Architecture.X64))
            {
                strawberryPerlDownloadUri = @"http://strawberryperl.com/download/5.24.0.1/strawberry-perl-5.24.0.1-64bit-portable.zip";
                strawberryPerlSha1 = @"40094b93fdab1057598e9474767d34e810a1c383";
            }
            else
            {
                strawberryPerlDownloadUri = @"http://strawberryperl.com/download/5.24.0.1/strawberry-perl-no64-5.24.0.1-32bit-portable.zip";
                strawberryPerlSha1 = @"64fe479f4caa0881fca59e88c97d9cf2181a5007";
            }

            var strawberryPerlZipName = "StrawberryPerl.zip";

            var fullZipPath = toolsPath + Path.DirectorySeparatorChar + strawberryPerlZipName;

            bool zipAlreadyExists = File.Exists(fullZipPath);

            if (zipAlreadyExists)
            {
                WriteLineToConsole("Discovered previous download. Verifying integrity.");

                // Just let it revert to false if hash doesn't match. The file
                // would simply be overwritten.
                zipAlreadyExists = VerifyFileHash(HashAlgorithmName.SHA1, fullZipPath, strawberryPerlSha1);

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
                var downloadTask = DownloadFile(strawberryPerlDownloadUri, toolsPath, null, strawberryPerlZipName);
                downloadTask.Wait();

                if (!VerifyFileHash(HashAlgorithmName.SHA1, fullZipPath, strawberryPerlSha1))
                {
                    throw new Exception("Downloaded file does not match expected hash.");
                }
            }

            // Before decompressing again, let's see if we can find an already
            // decompressed perl.exe.
            var decompressedPath = toolsPath + Path.DirectorySeparatorChar + "strawberryperl";

            string[] existingPerlPaths = new string[0];

            if(Directory.Exists(decompressedPath))
            {
                existingPerlPaths = Directory.GetFiles(decompressedPath, "perl.exe", SearchOption.AllDirectories);

                if (existingPerlPaths.Length > 0)
                {
                    return Directory.GetParent(existingPerlPaths[0]).FullName.ConvertToHostOsPath();       
                }
            }
            
            // If we reached here, then we need to decompress.
            DecompressArchive(fullZipPath, decompressedPath);            

            existingPerlPaths = Directory.GetFiles(toolsPath, "perl.exe", SearchOption.AllDirectories);

            if (existingPerlPaths.Length == 0)
            {
                WriteLineToConsole("Failed to find perl executable in extracted package.");
                return string.Empty;
            }

            return Directory.GetParent(existingPerlPaths[0]).FullName.ConvertToHostOsPath();
        }

        private string ConfigureNasm()
        {

            WriteLineToConsole("Searching for existing nasm installations...");

            var envVars = Environment.GetEnvironmentVariables();

            foreach (var variable in envVars.Keys)
            {
                var split = ((string)envVars[variable]).Split(Path.PathSeparator);

                foreach (var val in split)
                {
                    if (Directory.Exists(val))
                    {
                        string nasmPath = val.ConvertToHostOsPath() + Path.DirectorySeparatorChar + "nasm.exe";

                        if (File.Exists(nasmPath))
                        {
                            return Directory.GetParent(nasmPath).FullName.ConvertToHostOsPath();
                        }
                    }
                }
            }

            // Means we didn't find nasm.

            var toolsPath = WorkingDirectory + Path.DirectorySeparatorChar + "tools";
            string nasmDownloadUri = string.Empty;
            string nasmSha1 = string.Empty;


            if (System.Runtime.InteropServices.RuntimeInformation.OSArchitecture.HasFlag(System.Runtime.InteropServices.Architecture.X64))
            {
                nasmDownloadUri = @"http://www.nasm.us/pub/nasm/releasebuilds/2.12.02/win64/nasm-2.12.02-win64.zip";
                nasmSha1 = @"94756C0A427E65CD2AFE3DAC36F675BBAC3D89D8";
            }
            else
            {
                nasmDownloadUri = @"http://www.nasm.us/pub/nasm/releasebuilds/2.12.02/win32/nasm-2.12.02-win32.zip";
                nasmSha1 = @"07D7C742DCC1107D7A322DB7A3A19065D7D1CBB4";
            }

            var nasmZipName = "nasm.zip";

            var fullZipPath = toolsPath + Path.DirectorySeparatorChar + nasmZipName;

            bool zipAlreadyExists = File.Exists(fullZipPath);

            if (zipAlreadyExists)
            {
                WriteLineToConsole("Discovered previous download. Verifying integrity.");

                // Just let it revert to false if hash doesn't match. The file
                // would simply be overwritten.
                zipAlreadyExists = VerifyFileHash(HashAlgorithmName.SHA1, fullZipPath, nasmSha1);

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
                var downloadTask = DownloadFile(nasmDownloadUri, toolsPath, null, nasmZipName);
                downloadTask.Wait();

                if (!VerifyFileHash(HashAlgorithmName.SHA1, fullZipPath, nasmSha1))
                {
                    throw new Exception("Downloaded file does not match expected hash.");
                }
            }

            // Before decompressing again, let's see if we can find an already
            // decompressed perl.exe.
            var decompressedPath = toolsPath + Path.DirectorySeparatorChar + "nasm";

            string[] extractedNasmPaths = new string[0];

            if(Directory.Exists(decompressedPath))
            {
                extractedNasmPaths = Directory.GetFiles(decompressedPath, "nasm.exe", SearchOption.AllDirectories);

                if (extractedNasmPaths.Length > 0)
                {
                    return Directory.GetParent(extractedNasmPaths[0]).FullName.ConvertToHostOsPath();       
                }
            }

            // If we reached here, then we need to decompress.
            DecompressArchive(fullZipPath, decompressedPath);

            extractedNasmPaths = Directory.GetFiles(toolsPath, "nasm.exe", SearchOption.AllDirectories);

            if (extractedNasmPaths.Length == 0)
            {
                WriteLineToConsole("Failed to find nasm executable in extracted package.");
                return string.Empty;
            }

            return Directory.GetParent(extractedNasmPaths[0]).FullName.ConvertToHostOsPath();
        }
    }
}