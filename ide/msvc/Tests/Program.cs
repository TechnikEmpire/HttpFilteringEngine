/*
* Copyright © 2017 Jesse Nicholson
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

using HttpFe.Common;
using HttpFe.Managed;
using System;

namespace Tests
{
    internal class Program
    {
        private static volatile bool s_running = false;

        private static void Main(string[] args)
        {
            Console.CancelKeyPress += (sender, eArgs) =>
            {
                Console.WriteLine("Ctrl+C detected. Terminating.");
                s_running = false;
            };

            try
            {
                RunProgram();
            }
            catch(Exception e)
            {
                Console.WriteLine("Got error.");
                while(e != null)
                {
                    Console.WriteLine(e.Message);
                    Console.WriteLine(e.StackTrace);
                    e = e.InnerException;
                }
            }

            Console.WriteLine("Press any key to exit.");
            Console.ReadKey();
        }

        private static void RunProgram()
        {
            using(var engine = new HttpFilteringEngine(FirewallCheck, OnHttpMessageBegin, OnHttpMessageEnd, 0, 0, 0))
            {
                engine.OnInfo += OnInfo;
                engine.OnWarning += OnWarning;
                engine.OnError += OnError;

                engine.Start();
                s_running = true;

                while(s_running)
                {
                }                    

                engine.Stop();
            }
        }

        private static void OnHttpMessageBegin(
            string requestHeaders, byte[] requestBody,
            string responseHeaders, byte[] responseBody,
            out ProxyNextAction nextAction, out byte[] customBlockResponseData
            )
        {
            nextAction = ProxyNextAction.AllowAndIgnoreContentAndResponse;
            customBlockResponseData = null;
        }

        private static void OnHttpMessageEnd(
            string requestHeaders, byte[] requestBody,
            string responseHeaders, byte[] responseBody,
            out bool shouldBlock, out byte[] customBlockResponseData
            )
        {
            shouldBlock = false;
            customBlockResponseData = null;
        }

        private static bool FirewallCheck(string binAbsPath)
        {
            Console.WriteLine("Filtering application {0}.", binAbsPath);
            return true;
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
    }
}