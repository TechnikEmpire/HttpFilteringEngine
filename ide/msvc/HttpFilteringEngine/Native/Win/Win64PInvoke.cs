/*
* Copyright © 2017 Jesse Nicholson
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

using HttpFilteringEngine.Managed;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace HttpFilteringEngine.Native.Win
{
    internal class Win64PInvoke : AbstractEngine
    {
        private IntPtr m_engineHandle;

        public override bool IsRunning
        {
            get
            {
                if (m_engineHandle != IntPtr.Zero)
                {
                    return NativeMethods64.fe_ctl_is_running(m_engineHandle);
                }

                return false;
            }
        }

        public override ushort HttpListenerPort
        {
            get
            {
                if (m_engineHandle != IntPtr.Zero)
                {
                    return NativeMethods64.fe_ctl_get_http_listener_port(m_engineHandle);
                }

                return 0;
            }
        }

        public override ushort HttpsListenerPort
        {
            get
            {
                if (m_engineHandle != IntPtr.Zero)
                {
                    return NativeMethods64.fe_ctl_get_https_listener_port(m_engineHandle);
                }

                return 0;
            }
        }

        internal Win64PInvoke(string caBundleAbsPath, ushort preferredHttpListeningPort = 0, ushort preferredHttpsListeningPort = 0) : base(caBundleAbsPath, preferredHttpListeningPort, preferredHttpsListeningPort)
        {
            m_engineHandle = NativeMethods64.fe_ctl_create(NativeFirewallCbReference, caBundleAbsPath, (uint)caBundleAbsPath.Length, preferredHttpListeningPort, preferredHttpsListeningPort, (uint)Environment.ProcessorCount, NativeHttpMsgBeginCbReference, NativeHttpMsgEndCbReference, NativeOnInfoCbReference, NativeOnWarnCbReference, NativeOnErrorCbReference);

            if (m_engineHandle == IntPtr.Zero || m_engineHandle == new IntPtr(-1))
            {
                throw new Exception("Failed to create native engine instance.");
            }
        }

        public override bool Start()
        {
            if (m_engineHandle != IntPtr.Zero)
            {
                return NativeMethods64.fe_ctl_start(m_engineHandle);
            }

            return false;
        }

        public override void Stop()
        {
            if(m_engineHandle != IntPtr.Zero)
            {
                NativeMethods64.fe_ctl_stop(m_engineHandle);
            }
        }

        protected override void DisposeNativeEngine()
        {
            if (IsRunning)
            {
                Stop();
            }

            if (m_engineHandle != IntPtr.Zero && m_engineHandle != new IntPtr(-1))
            {
                NativeMethods64.fe_ctl_destroy(ref m_engineHandle);
            }
        }

        private class NativeMethods64
        {
            [DllImport(@"x64\HttpFilteringEngine.dll", EntryPoint = "fe_ctl_create", CallingConvention = CallingConvention.Cdecl)]
            public static extern IntPtr fe_ctl_create([MarshalAs(UnmanagedType.FunctionPtr)] NativeFirewallCheckCallback firewallCb, [In()] [MarshalAs(UnmanagedType.LPStr)] string caBundleAbsolutePath, uint caBundleAbsolutePathLength, ushort httpListenerPort, ushort httpsListenerPort, uint numThreads, [MarshalAs(UnmanagedType.FunctionPtr)] NativeHttpMessageBeginCallback onMessageBegin, [MarshalAs(UnmanagedType.FunctionPtr)] NativeHttpMessageEndCallback onMessageEnd, [MarshalAs(UnmanagedType.FunctionPtr)] NativeReportMessageCallback onInfo, [MarshalAs(UnmanagedType.FunctionPtr)] NativeReportMessageCallback onWarn, [MarshalAs(UnmanagedType.FunctionPtr)] NativeReportMessageCallback onError);


            /// Return Type: void
            ///ptr: PVOID*
            [DllImport(@"x64\HttpFilteringEngine.dll", EntryPoint = "fe_ctl_destroy", CallingConvention = CallingConvention.Cdecl)]
            public static extern void fe_ctl_destroy(ref IntPtr ptr);


            /// Return Type: void
            ///ptr: PVOID->void*
            [DllImport(@"x64\HttpFilteringEngine.dll", EntryPoint = "fe_ctl_destroy_unsafe", CallingConvention = CallingConvention.Cdecl)]
            public static extern void fe_ctl_destroy_unsafe(IntPtr ptr);


            /// Return Type: boolean
            ///ptr: PVOID->void*
            [DllImport(@"x64\HttpFilteringEngine.dll", EntryPoint = "fe_ctl_start", CallingConvention = CallingConvention.Cdecl)]
            [return: MarshalAs(UnmanagedType.I1)]
            public static extern bool fe_ctl_start(IntPtr ptr);


            /// Return Type: void
            ///ptr: PVOID->void*
            [DllImport(@"x64\HttpFilteringEngine.dll", EntryPoint = "fe_ctl_stop", CallingConvention = CallingConvention.Cdecl)]
            public static extern void fe_ctl_stop(IntPtr ptr);


            /// Return Type: boolean
            ///ptr: PVOID->void*
            [DllImport(@"x64\HttpFilteringEngine.dll", EntryPoint = "fe_ctl_is_running", CallingConvention = CallingConvention.Cdecl)]
            [return: MarshalAs(UnmanagedType.I1)]
            public static extern bool fe_ctl_is_running(IntPtr ptr);


            /// Return Type: uint16_t->unsigned short
            ///ptr: PVOID->void*
            [DllImport(@"x64\HttpFilteringEngine.dll", EntryPoint = "fe_ctl_get_http_listener_port", CallingConvention = CallingConvention.Cdecl)]
            public static extern ushort fe_ctl_get_http_listener_port(IntPtr ptr);


            /// Return Type: uint16_t->unsigned short
            ///ptr: PVOID->void*
            [DllImport(@"x64\HttpFilteringEngine.dll", EntryPoint = "fe_ctl_get_https_listener_port", CallingConvention = CallingConvention.Cdecl)]
            public static extern ushort fe_ctl_get_https_listener_port(IntPtr ptr);


            /// Return Type: void
            ///ptr: PVOID->void*
            ///bufferPP: char**
            ///bufferSize: size_t*
            [DllImport(@"x64\HttpFilteringEngine.dll", EntryPoint = "fe_ctl_get_rootca_pem", CallingConvention = CallingConvention.Cdecl)]
            public static extern void fe_ctl_get_rootca_pem(IntPtr ptr, ref IntPtr bufferPP, ref uint bufferSize);
        }
    }
}
