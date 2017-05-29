/*
* Copyright © 2017 Jesse Nicholson
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/


#pragma once

#using <mscorlib.dll>
#using <System.dll>

/// <summary>
/// Boost 1.58+ has issues with warning zlib/bzip io_streams. This is a non-issue in this case. 
/// As such, warning C4275 and C4251 are disabled in C++->Advanced->Disable Specific Warnings.
/// https://svn.boost.org/trac/boost/ticket/10911
/// </summary>

#include <msclr\marshal_cppstd.h>

using namespace System;
using namespace System::Runtime::InteropServices;

namespace Te {

	namespace HttpFilteringEngine
	{

		public ref class Engine
		{
			
		public:

			enum class ProxyNextAction : UInt32
			{
				AllowAndIgnoreContent = 0,
				AllowButRequestContentInspection = 1,
				DropConnection = 2,
				AllowAndIgnoreContentAndResponse = 3
			};

			/// <summary>
			/// Callback that is designed to verify if the binary at the supplied absolute path has
			/// firewall permission to access the internet.
			/// </summary>			
			delegate bool FirewallCheckHandler(System::String^ binaryAbsolutePath);

			/// <summary>
			/// Callback for receiving informational messages.
			/// </summary>
			delegate void MessageHandler(System::String^ message);

			delegate void HttpMessageBeginHandler(
				System::String^ requestHeaders, array<System::Byte>^ requestBody,
				System::String^ responseHeaders, array<System::Byte>^ responseBody,
				[Out] ProxyNextAction% nextAction, [Out] array<System::Byte>^% customBlockResponseData);

			delegate void HttpMessageEndHandler(
				System::String^ requestHeaders, array<System::Byte>^ requestBody,
				System::String^ responseHeaders, array<System::Byte>^ responseBody,
				[Out] bool% shouldBlock, [Out] array<System::Byte>^% customBlockResponseData);
			
			/// <summary>
			/// Constructs a new Engine.
			/// </summary>
			/// <param name="classificationFunc">
			/// A function that will be called as a last resort to attempt to classify the content of
			/// a request, to determine if that request should be blocked.
			/// </param>
			/// <param name="firewallCheckFunc">
			/// A function that will determine whether a binary at a specified absolute path has
			/// firewall permission to access the internet.
			/// </param>
			/// <param name="caBundleAbsPath">
			/// Absolute path to a CA bundle, such as the cURL/Mozilla ca-bundle. This bundle will be
			/// loaded and used for verifying all upstream server certificates.
			/// </param>
			/// <param name="blockedHtmlPage">
			/// HTML to display when a HTML payload is blocked.
			/// </param>
			/// <param name="httpListenerPort">
			/// The port that the proxy is to listen on for diverted plain TCP HTTP clients.
			/// Recommended value is zero. By setting the value to zero, this allows the OS to select
			/// an available port from the ephimeral port range.
			/// </param>
			/// <param name="httpsListenerPort">
			/// The port that the proxy is to listen on for diverted secure HTTP clients. Recommended
			/// value is zero. By setting the value to zero, this allows the OS to select an
			/// available port from the ephimeral port range.
			/// </param>
			/// <param name="numThreads">
			/// The number of threads to use to run against the underlying boost::asio::io_service
			/// that will drive all of the proxy functionality. If the supplied value is zero, the
			/// underlying Engine will automatically use the number of logical cores on the device.
			/// Be advised that these are the same threads responsible for running the filtering
			/// code.
			/// </param>
			Engine(FirewallCheckHandler^ firewallCheckFunc, HttpMessageBeginHandler^ httpMessageBeginFunc, HttpMessageEndHandler^ httpMessageEndFunc, System::String^ caBundleAbsPath, uint16_t httpListenerPort, uint16_t httpsListenerPort, uint32_t numThreads);

			/// <summary>
			/// Destructor, invokes finalizer as per docs here
			/// https://msdn.microsoft.com/library/ms177197(v=vs.100).aspx.
			/// </summary>
			~Engine();

			/// <summary>
			/// Finalizer for releasing unmanaged resources.
			/// </summary>
			!Engine();

			/// <summary>
			/// The absolute path to the CA bundle supplied at construction.
			/// </summary>
			property System::String^ CaBundleAbsolutePath
			{
			
			public:
				System::String^ get();

			private:
				void set(System::String^ value);

			}

			/// <summary>
			/// The HTTP listener port.
			/// </summary>
			property uint16_t HttpListenerPort
			{

			public:
				uint16_t get();

			private:
				void set(uint16_t value);

			}

			/// <summary>
			/// The HTTPS listener port.
			/// </summary>
			property uint16_t HttpsListenerPort
			{

			public:
				uint16_t get();

			private:
				void set(uint16_t value);

			}		

			/// <summary>
			/// Checks the current state of the Engine.
			/// </summary>
			property bool IsRunning
			{

			public:
				bool get();

			}

			// XXX TODO - By defining events this way, the compiler is nice to us and generates all
			// the code necessary to create a "real" event. There is one catch, the method to invoke
			// a broadcast through the event is public. The question is: do we need to care?

			/// <summary>
			/// Called whenever informational messages about non-critical events are generated by
			/// the Engine.
			/// </summary>
			event MessageHandler^ OnInfo;

			/// <summary>
			/// Called whenever informational messages about warnings are generated by the Engine.
			/// </summary>
			event MessageHandler^ OnWarning;

			/// <summary>
			/// Called whenever informational messages about handled errors are generated by the
			/// Engine.
			/// </summary>
			event MessageHandler^ OnError;

			/// <summary>
			/// Starts the Engine, which begins diverting plain TCP HTTP and secure HTTP clients
			/// through the proxy. It is recommended that, from a UI, this method be called from a
			/// BackgroundWorker.
			/// </summary>
			void Start();

			/// <summary>
			/// Stop the Engine. Shuts down the HTTP and HTTPS listeners, cancels all pending async
			/// operations and kills all diversion threads. It is recommended that, from a UI, this
			/// method be called from a BackgroundWorker. Since many threads are being joined, this
			/// operation can hang for a handful of seconds.
			/// </summary>
			void Stop();

			/// <summary>
			/// Gets the bytes for the current root CA, if any, in PEM format.
			/// </summary>
			/// <returns>
			/// An array containing the bytes for the current root CA in PEM format. If there is no
			/// current root CA in use, or an error occurred in the underlying engine, the array will
			/// be empty.
			/// </returns>
			array<System::Byte>^ GetRootCaPEM();

		private:

			/// <summary>
			/// In order to be able to supply callbacks from the managed side to the unmanaged side,
			/// they need to be wrapped in a delegate and then the delegate needs to be processed by
			/// Marshal::GetFunctionPointerForDelegate(). This allows the CLR to do some sleazy
			/// black magic, turning our class member functions into plain C function pointers.
			/// 
			/// This is the unmanaged callback delegate for checking firewall permissions.
			/// </summary>			
			[UnmanagedFunctionPointer(CallingConvention::Cdecl)]
			delegate bool UnmanagedFirewallCheckCallback(const char* binaryAbsolutePath, const size_t binaryAbsolutePathLength);

			/// <summary>
			/// See notes on UnmanagedFirewallCheckCallback. This is the managed, unmanaged callback
			/// delegate for onInfo, onWarn and onError.
			/// </summary>
			[UnmanagedFunctionPointer(CallingConvention::Cdecl)]
			delegate void UnmanagedMessageCallback(const char* message, const size_t messageLength);

			[UnmanagedFunctionPointer(CallingConvention::Cdecl)]
			delegate void UnmanagedOnHttpMessageBeginCallback(
				const char* requestHeaders, const uint32_t requestHeadersLength, const char* requestBody, const uint32_t requestBodyLength,
				const char* responseHeaders, const uint32_t responseHeadersLength, const char* responseBody, const uint32_t responseBodyLength,
				uint32_t* nextAction, char** customBlockResponse, uint32_t* customBlockResponseLength
			);

			[UnmanagedFunctionPointer(CallingConvention::Cdecl)]
			delegate void UnmanagedOnHttpMessageEndCallback(
				const char* requestHeaders, const uint32_t requestHeadersLength, const char* requestBody, const uint32_t requestBodyLength,
				const char* responseHeaders, const uint32_t responseHeadersLength, const char* responseBody, const uint32_t responseBodyLength,
				bool* shouldBlock, char** customBlockResponse, uint32_t* customBlockResponseLength
			);

			/// <summary>
			/// Firewall check callback to supply to the unmanaged side.
			/// </summary>
			UnmanagedFirewallCheckCallback^ m_unmanagedFirewallCheckCallback = nullptr;

			/// <summary>
			/// OnInfo callback to supply to the unmanaged side.
			/// </summary>
			UnmanagedMessageCallback^ m_unmanagedOnInfoCallback = nullptr;

			/// <summary>
			/// OnWarning callback to supply to the unmanaged side.
			/// </summary>
			UnmanagedMessageCallback^ m_unmanagedOnWarningCallback = nullptr;

			/// <summary>
			/// OnError callback to supply to the unmanaged side.
			/// </summary>
			UnmanagedMessageCallback^ m_unmanagedOnErrorCallback = nullptr;

			/// <summary>
			/// Http message begin callback for unmanaged side.
			/// </summary>
			UnmanagedOnHttpMessageBeginCallback^ m_unmanagedOnHttpMessageBeginCallback = nullptr;

			/// <summary>
			/// Http message end callback for unmanaged side.
			/// </summary>
			UnmanagedOnHttpMessageEndCallback^ m_unmanagedOnHttpMessageEndCallback = nullptr;

			/// <summary>
			/// Pointer to the unmanaged Engine structure.
			/// </summary>
			PVOID m_handle = nullptr;

			/// <summary>
			/// Absolute path to the CA bundle to be used, supplied at construction.
			/// </summary>
			System::String^ m_caBundleAbsPath = nullptr;

			/// <summary>
			/// Port on which the proxy should list for HTTP clients. Supplied at construction,
			/// never used again.
			/// </summary>
			uint16_t m_httpListenerPort = 0;

			/// <summary>
			/// Port on which the proxy should list for HTTPS clients. Supplied at construction,
			/// never used again.
			/// </summary>
			uint16_t m_httpsListenerPort = 0;

			/// <summary>
			/// Number of threads to use to drive the underlying io_service. Supplied at construction.
			/// </summary>
			uint32_t m_numThreads = 0;

			/// <summary>
			/// The callback to be used to check the firewall permissions of a specific binary.
			/// </summary>
			FirewallCheckHandler^ m_onFirewallCallback = nullptr;

			HttpMessageBeginHandler^ m_onHttpMessageBeginCallback = nullptr;

			HttpMessageEndHandler^ m_onHttpMessageEndCallback = nullptr;

			/// <summary>
			/// Initializes the unmanaged structure, configures callbacks.
			/// </summary>
			void Init();

			// All of the following methods are callbacks that we provide to the unmanaged side, even if the user
			// doesn't ask for any of them. We supply them, so we're always hooked, then give the user the option
			// to subscribe and unsubscribe at-will throughout the lifetime of this object. Each and every one
			// of these callbacks simply verifies supplied data, then invokes the corresponding event with the
			// converted arguments. The firewall check is the exception, only in the sense that does not invoke
			// an event broadcaster, but rather the sole supplied managed firewall callback function.

			bool UnmanagedFirewallCheck(const char* binaryAbsolutePath, const size_t binaryAbsolutePathLength);

			void UnmanagedOnInfo(const char* message, const size_t messageLength);

			void UnmanagedOnWarning(const char* message, const size_t messageLength);

			void UnmanagedOnError(const char* message, const size_t messageLength);
			
			void UnmanagedHttpMessageBegin(
				const char* requestHeaders, const uint32_t requestHeadersLength, const char* requestBody, const uint32_t requestBodyLength,
				const char* responseHeaders, const uint32_t responseHeadersLength, const char* responseBody, const uint32_t responseBodyLength,
				uint32_t* nextAction, char** customBlockResponse, uint32_t* customBlockResponseLength
			);

			void UnmanagedHttpMessageEnd(
				const char* requestHeaders, const uint32_t requestHeadersLength, const char* requestBody, const uint32_t requestBodyLength,
				const char* responseHeaders, const uint32_t responseHeadersLength, const char* responseBody, const uint32_t responseBodyLength,
				bool* shouldBlock, char** customBlockResponse, uint32_t* customBlockResponseLength
			);

		};

	} /* namespace HttpFilteringEngine */
} /* namespace Te */
