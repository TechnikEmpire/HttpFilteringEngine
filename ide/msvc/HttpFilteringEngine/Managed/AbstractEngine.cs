/*
* Copyright © 2017 Jesse Nicholson
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

using HttpFilteringEngine.Native.Win;
using System;
using System.Runtime.InteropServices;

namespace HttpFilteringEngine.Managed
{
    public delegate bool FirewallCheckCallback(string binaryAbsolutePath);

    public delegate void EngineMessageCallback(string message);

    public delegate void ResponseWriter(byte[] responseData);

    public delegate void HttpMessageBeginCallback(string requestHeaders, byte[] requestBody, string responseHeaders, byte[] responseBody, out ProxyNextAction nextAction, ResponseWriter responseWriter);

    public delegate void HttpMessageEndCallback(string requestHeaders, byte[] requestBody, string responseHeaders, byte[] responseBody, out bool shouldBlock, ResponseWriter responseWriter);

    public abstract class AbstractEngine : IDisposable
    {
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        protected delegate bool NativeFirewallCheckCallback([In()] [MarshalAs(UnmanagedType.LPStr)] string binaryAbsolutePath, IntPtr binaryAbsolutePathLength);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        protected delegate void NativeReportMessageCallback([In()] [MarshalAs(UnmanagedType.LPStr)] string message, uint messageLength);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        protected delegate void NativeCustomResponseStreamWriter([In()] byte[] data, uint dataLength);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        protected delegate void NativeHttpMessageBeginCallback([In()] [MarshalAs(UnmanagedType.LPStr)] string requestHeaders, uint requestHeadersLength, [In()] IntPtr requestBody, uint requestBodyLength, [In()] [MarshalAs(UnmanagedType.LPStr)] string responseHeaders, uint responseHeadersLength, [In()] IntPtr responseBody, uint responseBodyLength, ref uint nextAction, NativeCustomResponseStreamWriter customBlockResponseStreamWriter);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        protected delegate void NativeHttpMessageEndCallback([In()] [MarshalAs(UnmanagedType.LPStr)] string requestHeaders, uint requestHeadersLength, [In()] IntPtr requestBody, uint requestBodyLength, [In()] [MarshalAs(UnmanagedType.LPStr)] string responseHeaders, uint responseHeadersLength, [In()] IntPtr responseBody, uint responseBodyLength, ref bool shouldBlock, NativeCustomResponseStreamWriter customBlockResponseStreamWriter);

        public static AbstractEngine Create(string caBundleAbsPath, ushort preferredHttpListeningPort = 0, ushort preferredHttpsListeningPort = 0)
        {            
            if(Environment.OSVersion.Platform == PlatformID.Win32NT)
            {
                switch(Environment.Is64BitProcess)
                {
                    case true:
                        {
                            return new Win64PInvoke(caBundleAbsPath, preferredHttpListeningPort, preferredHttpsListeningPort);
                        }

                    case false:
                        {
                            return new Win32PInvoke(caBundleAbsPath, preferredHttpListeningPort, preferredHttpsListeningPort);
                        }
                }
            }
            else
            {
                throw new Exception("No implementation presently available for this platform.");
            }

            return null;
        }

        protected NativeFirewallCheckCallback NativeFirewallCbReference
        {
            get;
            private set;
        }

        protected NativeHttpMessageBeginCallback NativeHttpMsgBeginCbReference
        {
            get;
            private set;
        }

        protected NativeHttpMessageEndCallback NativeHttpMsgEndCbReference
        {
            get;
            private set;
        }

        protected NativeReportMessageCallback NativeOnInfoCbReference
        {
            get;
            private set;
        }

        protected NativeReportMessageCallback NativeOnWarnCbReference
        {
            get;
            private set;
        }

        protected NativeReportMessageCallback NativeOnErrorCbReference
        {
            get;
            private set;
        }

        public FirewallCheckCallback FirewallCheckCallback
        {
            get;
            set;
        }

        public HttpMessageBeginCallback HttpMessageBeginCallback
        {
            get;
            set;
        }

        public HttpMessageEndCallback HttpMessageEndCallback
        {
            get;
            set;
        }

        public EngineMessageCallback OnInfo
        {
            get;
            set;
        }

        public EngineMessageCallback OnWarning
        {
            get;
            set;
        }

        public EngineMessageCallback OnError
        {
            get;
            set;
        }

        public abstract bool IsRunning
        {
            get;
        }

        public abstract ushort HttpListenerPort
        {
            get;
        }

        public abstract ushort HttpsListenerPort
        {
            get;
        }

        /// <summary>
        /// Constructs a new AbstractEngine instance. 
        /// </summary>
        /// <param name="caBundleAbsPath">
        /// Ignored.
        /// </param>
        /// <param name="preferredHttpListeningPort">
        /// Ignored.
        /// </param>
        /// <param name="preferredHttpsListeningPort">
        /// Ignored.
        /// </param>
        internal AbstractEngine(string caBundleAbsPath, ushort preferredHttpListeningPort = 0, ushort preferredHttpsListeningPort = 0)
        {
            NativeFirewallCbReference = new NativeFirewallCheckCallback(OnFirewallCheckCallback);
            NativeHttpMsgBeginCbReference = new NativeHttpMessageBeginCallback(OnEngineHttpMessageBegin);
            NativeHttpMsgEndCbReference = new NativeHttpMessageEndCallback(OnEngineHttpMessageEnd);
            NativeOnInfoCbReference = new NativeReportMessageCallback(OnEngineInfo);
            NativeOnWarnCbReference = new NativeReportMessageCallback(OnEngineWarning);
            NativeOnErrorCbReference = new NativeReportMessageCallback(OnEngineError);
        }

        private bool OnFirewallCheckCallback([In] [MarshalAs(UnmanagedType.LPStr)] string binaryAbsolutePath, IntPtr binaryAbsolutePathLength)
        {
            var result = FirewallCheckCallback?.Invoke(binaryAbsolutePath);

            return result.HasValue ? result.Value : false;
        }

        private void OnEngineHttpMessageBegin([In] [MarshalAs(UnmanagedType.LPStr)] string requestHeaders, uint requestHeadersLength, [In] IntPtr requestBody, uint requestBodyLength, [In] [MarshalAs(UnmanagedType.LPStr)] string responseHeaders, uint responseHeadersLength, [In] IntPtr responseBody, uint responseBodyLength, ref uint nextAction, NativeCustomResponseStreamWriter customBlockResponseStreamWriter)
        {
            byte[] requestBodyManaged = null;
            byte[] responseBodyManaged = null;

            if(requestBody != IntPtr.Zero)
            {
                requestBodyManaged = new byte[requestBodyLength];
                Marshal.Copy(requestBody, requestBodyManaged, 0, requestBodyManaged.Length);
            }

            if (responseBody != IntPtr.Zero)
            {
                responseBodyManaged = new byte[requestBodyLength];
                Marshal.Copy(responseBody, responseBodyManaged, 0, responseBodyManaged.Length);
            }
            
            ResponseWriter thisWriter = (byte[] responseData) =>
            {
                var myNativeWriter = customBlockResponseStreamWriter;
                if (myNativeWriter == null)
                {
                    OnWarning?.Invoke("Native response writers exhausted.");
                }

                myNativeWriter?.Invoke(responseData, (uint)responseData.Length);

                GC.KeepAlive(myNativeWriter);
            };

            var managedNextAction = ProxyNextAction.AllowAndIgnoreContentAndResponse;

            HttpMessageBeginCallback?.Invoke(requestHeaders, requestBodyManaged, responseHeaders, responseBodyManaged, out managedNextAction, thisWriter);

            nextAction = (uint)managedNextAction;
        }

        private void OnEngineHttpMessageEnd([In] [MarshalAs(UnmanagedType.LPStr)] string requestHeaders, uint requestHeadersLength, [In] IntPtr requestBody, uint requestBodyLength, [In] [MarshalAs(UnmanagedType.LPStr)] string responseHeaders, uint responseHeadersLength, [In] IntPtr responseBody, uint responseBodyLength, ref bool shouldBlock, NativeCustomResponseStreamWriter customBlockResponseStreamWriter)
        {
            byte[] requestBodyManaged = null;
            byte[] responseBodyManaged = null;

            if (requestBody != IntPtr.Zero)
            {
                requestBodyManaged = new byte[requestBodyLength];
                Marshal.Copy(requestBody, requestBodyManaged, 0, requestBodyManaged.Length);
            }

            if (responseBody != IntPtr.Zero)
            {
                responseBodyManaged = new byte[requestBodyLength];
                Marshal.Copy(responseBody, responseBodyManaged, 0, responseBodyManaged.Length);
            }

            ResponseWriter thisWriter = (byte[] responseData) =>
            {
                
                var myNativeWriter = customBlockResponseStreamWriter;
                if (myNativeWriter == null)
                {
                    OnWarning?.Invoke("Native response writers exhausted.");
                }

                myNativeWriter?.Invoke(responseData, (uint)responseData.Length);

                GC.KeepAlive(myNativeWriter);
            };

            var shouldBlockManaged = false;

            HttpMessageEndCallback?.Invoke(requestHeaders, requestBodyManaged, responseHeaders, responseBodyManaged, out shouldBlockManaged, thisWriter);

            shouldBlock = shouldBlockManaged;
        }

        private void OnEngineInfo(string message, uint messageLength)
        {
            OnInfo?.Invoke(message);
        }

        private void OnEngineWarning(string message, uint messageLength)
        {
            OnWarning?.Invoke(message);
        }

        private void OnEngineError(string message, uint messageLength)
        {
            OnError?.Invoke(message);
        }

        public abstract bool Start();

        public abstract void Stop();

        protected abstract void DisposeNativeEngine();

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    // TODO: dispose managed state (managed objects).
                }

                if(IsRunning)
                {
                    Stop();
                }

                DisposeNativeEngine();

                disposedValue = true;
            }
        }

        // TODO: override a finalizer only if Dispose(bool disposing) above has code to free unmanaged resources.
        // ~AbstractEngine() {
        //   // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
        //   Dispose(false);
        // }

        // This code added to correctly implement the disposable pattern.
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
            // TODO: uncomment the following line if the finalizer is overridden above.
            // GC.SuppressFinalize(this);
        }
        #endregion
    }
}