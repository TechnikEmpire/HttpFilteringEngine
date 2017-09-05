/*
* Copyright © 2017 Jesse Nicholson
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

using HttpFe.Common;
using System;
using System.IO;
using System.Linq;
using System.Reflection;

namespace HttpFe.Managed
{
    internal class StaticAssemblyResolver
    {
        private static readonly Assembly s_targetAssembly;

        /// <summary>
        /// Resolves the native mixed managed C++/CLI assembly automatically based on the current
        /// process architecture. Runs once, loads the target assembly into the app domain only once.
        /// </summary>
        static StaticAssemblyResolver()
        {
            var baseDir = Directory.GetParent(typeof(StaticAssemblyResolver).Assembly.Location).FullName;

            if(Environment.Is64BitProcess)
            {
                baseDir = Path.Combine(baseDir, "x64");
            }
            else
            {
                baseDir = Path.Combine(baseDir, "x86");
            }

            try
            {
                s_targetAssembly = Assembly.LoadFrom(Path.Combine(baseDir, "HttpFilteringEngine.dll"));
            }
            catch(Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }

        /// <summary>
        /// Gets a new instance of a trainer from the dynamically resolved mixed managed C++/CLI library. 
        /// </summary>
        /// <returns>
        /// A new instance of the trainer class. 
        /// </returns>
        public static IHttpFilteringEngine GetFilteringEngine(FirewallCheckHandler firewallCheckFunc, HttpMessageBeginHandler httpMessageBeginFunc, HttpMessageEndHandler httpMessageEndFunc, string caBundleAbsPath = "none", ushort httpListenerPort = 0, ushort httpsListenerPort = 0, uint numThreads = 0)
        {
            var exportedFeatureExtractors = s_targetAssembly.ExportedTypes.Where(x => x.GetInterfaces().Contains(typeof(IHttpFilteringEngine)));

            var res = exportedFeatureExtractors.FirstOrDefault();

            if(res != null)
            {
                IHttpFilteringEngine typedExport = (IHttpFilteringEngine)Activator.CreateInstance(res, firewallCheckFunc, httpMessageBeginFunc, httpMessageEndFunc, caBundleAbsPath, httpListenerPort, httpsListenerPort, numThreads);
                return typedExport;
            }

            return null;
        }
    }
}