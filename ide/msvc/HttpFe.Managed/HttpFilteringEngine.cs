/*
* Copyright © 2017 Jesse Nicholson
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

using HttpFe.Common;
using HttpFe.Common.Extensions;
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace HttpFe.Managed
{
    public class HttpFilteringEngine : IHttpFilteringEngine, IDisposable
    {
        private IHttpFilteringEngine m_nativeEngine;

        public event MessageHandler OnInfo;

        public event MessageHandler OnWarning;

        public event MessageHandler OnError;

        private string m_tmpCaBundlePath = string.Empty;

        public HttpFilteringEngine(FirewallCheckHandler firewallCheckFunc, HttpMessageBeginHandler httpMessageBeginFunc, HttpMessageEndHandler httpMessageEndFunc, string caBundleAbsPath = "none", ushort httpListenerPort = 0, ushort httpsListenerPort = 0, uint numThreads = 0)
        {
            m_nativeEngine = StaticAssemblyResolver.GetFilteringEngine(firewallCheckFunc, httpMessageBeginFunc, httpMessageEndFunc, caBundleAbsPath, httpListenerPort, httpsListenerPort, numThreads);

            InitListeners();
        }

        public HttpFilteringEngine(FirewallCheckHandler firewallCheckFunc, HttpMessageBeginHandler httpMessageBeginFunc, HttpMessageEndHandler httpMessageEndFunc, ushort httpListenerPort = 0, ushort httpsListenerPort = 0, uint numThreads = 0)
        {
            BuildCaBundleWithLocalTrustedCerts();

            m_nativeEngine = StaticAssemblyResolver.GetFilteringEngine(firewallCheckFunc, httpMessageBeginFunc, httpMessageEndFunc, m_tmpCaBundlePath, httpListenerPort, httpsListenerPort, numThreads);

            InitListeners();
        }

        private void BuildCaBundleWithLocalTrustedCerts()
        {
            var caCertPackURI = "CitadelService.Resources.ca-cert.pem";
            StringBuilder caFileBuilder = new StringBuilder();
            using(var resourceStream = Assembly.GetExecutingAssembly().GetManifestResourceStream(caCertPackURI))
            {
                if(resourceStream != null && resourceStream.CanRead)
                {
                    using(TextReader tsr = new StreamReader(resourceStream))
                    {
                        caFileBuilder = new StringBuilder(tsr.ReadToEnd());
                    }
                }
            }

            caFileBuilder.AppendLine();

            // Get Microsoft root authorities. We need this in order to permit Windows Update and
            // such in the event that it is forced through the filter.
            var toTrust = new List<StoreName>() {
                StoreName.Root,
                StoreName.AuthRoot,
                StoreName.CertificateAuthority,
                StoreName.TrustedPublisher,
                StoreName.TrustedPeople
            };

            foreach(var trust in toTrust)
            {
                X509Store localStore = new X509Store(trust, StoreLocation.LocalMachine);

                localStore.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                foreach(var cert in localStore.Certificates)
                {
                    caFileBuilder.AppendLine(cert.ExportToPem());
                }

                localStore.Close();
            }

            // Dump the text to the local file system.
            if(m_tmpCaBundlePath == null || m_tmpCaBundlePath == string.Empty)
            {
                m_tmpCaBundlePath = Path.GetTempFileName();
            }

            File.WriteAllText(m_tmpCaBundlePath, caFileBuilder.ToString());
        }

        private void InitListeners()
        {
            m_nativeEngine.OnInfo += (string message) =>
            {
                OnInfo?.Invoke(message);
            };

            m_nativeEngine.OnWarning += (string message) =>
            {
                OnWarning?.Invoke(message);
            };

            m_nativeEngine.OnError += (string message) =>
            {
                OnError?.Invoke(message);
            };
        }

        public string CaBundleAbsolutePath
        {
            get
            {
                return m_nativeEngine.CaBundleAbsolutePath;
            }
        }

        public ushort HttpListenerPort
        {
            get
            {
                return m_nativeEngine.HttpListenerPort;
            }
        }

        public ushort HttpsListenerPort
        {
            get
            {
                return m_nativeEngine.HttpsListenerPort;
            }
        }

        public bool IsRunning
        {
            get
            {
                return m_nativeEngine.IsRunning;
            }
        }

        public byte[] RootCaPEM
        {
            get
            {
                return m_nativeEngine.RootCaPEM;
            }
        }

        public void Start()
        {
            m_nativeEngine.Start();
        }

        public void Stop()
        {
            m_nativeEngine.Stop();
        }

        public void Dispose()
        {
            if(m_tmpCaBundlePath != null && m_tmpCaBundlePath != string.Empty)
            {
                try
                {
                    if(File.Exists(m_tmpCaBundlePath))
                    {
                        File.Delete(m_tmpCaBundlePath);
                    }
                }
                catch { }
            }
        }
    }
}