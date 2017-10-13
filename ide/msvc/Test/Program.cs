/*
* Copyright © 2017 Jesse Nicholson
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

using HttpFilteringEngine.Managed;
using System;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading;

namespace Tests
{
    internal class Program
    {
        private static ManualResetEvent s_rstEvent = new ManualResetEvent(false);

        private static readonly DateTime s_Epoch = new DateTime(1970, 1, 1);
        private static readonly string s_EpochHttpDateTime = s_Epoch.ToString("r");

        private static string s_blockedHtmlPage = string.Empty;

        private static void Main(string[] args)
        {
            //AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException;            

            var path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Resources", "BlockedPage.html");
            if (File.Exists(path))
            {
                s_blockedHtmlPage = File.ReadAllText(path);
            }
            else
            {
                Console.WriteLine("Cannot read from packed block page file.");
                Environment.Exit(-1);
            }

            Console.CancelKeyPress += (sender, eArgs) =>
            {
                Console.WriteLine("Ctrl+C detected. Terminating.");
                s_rstEvent.Set();
            };

            try
            {
                RunProgram();
            }
            catch (Exception e)
            {
                Console.WriteLine("Got error.");
                while (e != null)
                {
                    Console.WriteLine(e.Message);
                    Console.WriteLine(e.StackTrace);
                    e = e.InnerException;
                }
            }

            Console.WriteLine("Press any key to exit.");
            Console.ReadKey();
        }

        private static void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            Console.WriteLine("Unhandled exception!");
            Exception ex = (Exception)e.ExceptionObject;

            while(ex != null)
            {
                Console.WriteLine(ex.Message);
                Console.WriteLine(ex.StackTrace);
                ex = ex.InnerException;
            }
        }

        private static void RunProgram()
        {
            var caPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "cacert-2017-09-20.pem");
            using (var engine = AbstractEngine.Create(caPath, 0, 0))
            {
                engine.OnInfo = OnInfo;
                engine.OnWarning = OnWarning;
                engine.OnError = OnError;

                engine.FirewallCheckCallback = FirewallCheck;
                engine.HttpMessageBeginCallback = OnHttpMessageBegin;
                engine.HttpMessageEndCallback = OnHttpMessageEnd;

                engine.Start();
                s_rstEvent.WaitOne();

                engine.Stop();
            }
        }

        private static void OnHttpMessageBegin(
            string requestHeaders, byte[] requestBody,
            string responseHeaders, byte[] responseBody,
            out ProxyNextAction nextAction, ResponseWriter responseWriter
            )
        {
            Console.WriteLine("On message begin");
            
            try
            {
                if (requestHeaders.IndexOf("yourgreenhomes.ca", StringComparison.OrdinalIgnoreCase) != -1)
                {
                    if (responseHeaders != null && responseHeaders.IndexOf("/html") != -1)
                    {
                        var blockedResponse = GetBlockedResponse();

                        responseWriter(blockedResponse);

                        nextAction = ProxyNextAction.DropConnection;
                        return;
                    }
                }
                
            }
            catch(Exception e)
            {
                while(e != null)
                {
                    Console.WriteLine(e.Message);
                    Console.WriteLine(e.StackTrace);
                    e = e.InnerException;
                }
            }

            nextAction = ProxyNextAction.AllowAndIgnoreContent;
        }

        private static void OnHttpMessageEnd(
            string requestHeaders, byte[] requestBody,
            string responseHeaders, byte[] responseBody,
            out bool shouldBlock, ResponseWriter responseWriter
            )
        {   
            shouldBlock = false;
        }

        private static bool FirewallCheck(string binAbsPath)
        {
            Console.WriteLine("Filtering application {0}.", binAbsPath);
            return binAbsPath.IndexOf("firefox", StringComparison.OrdinalIgnoreCase) != -1;
        }

        private static void OnInfo(string message)
        {
            Console.WriteLine("INFO {0}", message);
        }

        private static void OnWarning(string message)
        {
            Console.WriteLine("WARNING {0}", message);
        }

        private static void OnError(string message)
        {
            Console.WriteLine("ERROR {0}", message);
        }

        private static byte[] GetBlockedResponse(string httpVersion = "1.1", bool htmlPage = true)
        {
            switch (htmlPage)
            {
                default:
                case false:
                    {
                        return Encoding.UTF8.GetBytes(string.Format("HTTP/{0} 204 No Content\r\nDate: {1}\r\nExpires: {2}\n\nContent-Length: 0\r\n\r\n", httpVersion, DateTime.UtcNow.ToString("r"), s_EpochHttpDateTime));
                    }

                case true:
                    {
                        return Encoding.UTF8.GetBytes(string.Format("HTTP/{0} 20O OK\r\nDate: {1}\r\nExpires: {2}\r\nContent-Type: text/html\r\nContent-Length: {3}\r\n\r\n{4}\r\n\r\n", httpVersion, DateTime.UtcNow.ToString("r"), s_EpochHttpDateTime, s_blockedHtmlPage.Length, s_blockedHtmlPage));
                    }
            }
        }
    }
}