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

#pragma once

#using <mscorlib.dll>
#using <System.dll>

/// <summary>
/// Boost 1.58+ has issues with warning zlib/bzip io_streams. This is a non-issue in this case. 
/// As such, warning C4275 and C4251 are disabled in C++->Advanced->Disable Specific Warnings.
/// https://svn.boost.org/trac/boost/ticket/10911
/// </summary>

#pragma managed(push, off)
#include "HttpFilteringEngineCAPI.h"
#pragma managed(pop)

#include <msclr\marshal_cppstd.h>

using namespace System;
using namespace System::Runtime::InteropServices;

namespace Te {

	namespace HttpFilteringEngine
	{

		public ref class Engine
		{
			
		public:

			/// <summary>
			/// Callback that is designed to verify if the binary at the supplied absolute path has
			/// firewall permission to access the internet.
			/// </summary>
			delegate bool OnFirewallCheckCallback(System::String^ binaryAbsolutePath);

			/// <summary>
			/// Callback for receiving informational messages.
			/// </summary>
			delegate void OnMessageCallback(System::String^ message);

			/// <summary>
			/// Callback for receiving information about blocked requests.
			/// </summary>
			delegate void OnReportRequestBlockedCallback(uint8_t category, uint32_t payloadSizeBlocked, System::String^ fullRequest);

			/// <summary>
			/// Callback for receiving information about removed HTML elements from HTML payloads.
			/// </summary>
			delegate void OnReportElementsBlockedCallback(uint32_t numElementsRemoved, System::String^ fullRequest);

			/// <summary>
			/// Constructs a new Engine.
			/// </summary>
			/// <param name="firewallCheckFunc">
			/// A function that will determine whether a binary at a specified absolute path has
			/// firewall permission to access the internet.
			/// </param>
			/// <param name="caBundleAbsPath">
			/// Absolute path to a CA bundle, such as the cURL/Mozilla ca-bundle. This bundle will
			/// be loaded and used for verifying all upstream server certificates.
			/// </param>
			/// <param name="httpListenerPort">
			/// The port that the proxy is to listen on for diverted plain TCP HTTP clients.
			/// Recommended value is zero. By setting the value to zero, this allows the OS to
			/// select an available port from the ephimeral port range.
			/// </param>
			/// <param name="httpsListenerPort">
			/// The port that the proxy is to listen on for diverted secure HTTP clients.
			/// Recommended value is zero. By setting the value to zero, this allows the OS to
			/// select an available port from the ephimeral port range.
			/// </param>
			/// <param name="numThreads">
			/// The number of threads to use to run against the underlying boost::asio::io_service
			/// that will drive all of the proxy functionality. If the supplied value is zero, the
			/// underlying Engine will automatically use the number of logical cores on the device.
			/// Be advised that these are the same threads responsible for running the filtering
			/// code.
			/// </param>
			Engine(OnFirewallCheckCallback^ firewallCheckFunc, System::String^ caBundleAbsPath, uint16_t httpListenerPort, uint16_t httpsListenerPort, uint32_t numThreads);

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
			event OnMessageCallback^ OnInfo;

			/// <summary>
			/// Called whenever informational messages about warnings are generated by the Engine.
			/// </summary>
			event OnMessageCallback^ OnWarning;

			/// <summary>
			/// Called whenever informational messages about handled errors are generated by the
			/// Engine.
			/// </summary>
			event OnMessageCallback^ OnError;

			/// <summary>
			/// Called whenever a request is reported as having been blocked.
			/// </summary>
			event OnReportRequestBlockedCallback^ OnRequestBlocked;

			/// <summary>
			/// Called whenever HTML elements are removed from an HTML payload.
			/// </summary>
			event OnReportElementsBlockedCallback^ OnElementsBlocked;

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
			/// Attempts to load an file containing Adblock Plus formatted filters and CSS
			/// selectors.
			/// </summary>
			/// <param name="listFilePath">
			/// The absolute path to the filter list.
			/// </param>
			/// <param name="listCategory">
			/// The category to assign to the rules loaded from the list. User defined, but must be
			/// non-zero.
			/// </param>
			/// <param name="flushExistingInCategory">
			/// Whether or not to flush rules that have the same category set the one supplied
			/// before loading the new rules from the supplied filter list.
			/// </param>
			/// <param name="rulesLoaded">
			/// The total number of rules successfully loaded and parsed from the source.
			/// </param>
			/// <param name="rulesFailed">
			/// The total number of rules that failed to load and or be parsed from the source.
			/// </param>
			void LoadAbpFormattedFile(
				System::String^ listFilePath, 
				uint8_t listCategory, 
				bool flushExistingInCategory,
				[Out] uint32_t% rulesLoaded,
				[Out] uint32_t% rulesFailed
				);

			/// <summary>
			/// Attempts to load Adblock Plus formatted filters and CSS selectors from the supplied
			/// list string.
			/// </summary>
			/// <param name="list">
			/// The filter list string.
			/// </param>
			/// <param name="listCategory">
			/// The category to assign to the rules loaded from the list. User defined, but must be
			/// non-zero.
			/// </param>
			/// <param name="flushExistingInCategory">
			/// Whether or not to flush rules that have the same category set the one supplied
			/// before loading the new rules from the supplied filter list.
			/// </param>
			/// <param name="rulesLoaded">
			/// The total number of rules successfully loaded and parsed from the source.
			/// </param>
			/// <param name="rulesFailed">
			/// The total number of rules that failed to load and or be parsed from the source.
			/// </param>
			void LoadAbpFormattedString(
				System::String^ list, 
				uint8_t listCategory, 
				bool flushExistingInCategory,
				[Out] uint32_t% rulesLoaded,
				[Out] uint32_t% rulesFailed
				);

			/// <summary>
			/// Unloads any and all rules assigned to the given category.
			/// </summary>
			/// <param name="category">
			/// The category for which to unload all rules.
			/// </param>
			void UnloadAllRulesForCategory(const uint8_t category);

			/// <summary>
			/// Checks if the specified option is enabled.
			/// </summary>
			/// <param name="option">
			/// The option, represented by a 32 bit unsigned integer. If there are any options for
			/// your platform, a header with an enum class specifying available options would have
			/// been provided. Note that available options do not span the max size of the supplied
			/// integer value. If an option outside the preset size of total available options is
			/// supplied, return value will always be false.
			/// </param>
			/// <returns>
			/// True of the specified option is enabled, false otherwise.
			/// </returns>
			bool IsOptionEnabled(uint32_t option);

			/// <summary>
			/// Sets whether the supplied option is enabled or not.
			/// </summary>
			/// <param name="option">
			/// The option, represented by a 32 bit unsigned integer. If there are any options for
			/// your platform, a header with an enum class specifying available options would have
			/// been provided. Note that available options do not span the max size of the supplied
			/// integer value. If an option outside the preset size of total available options is
			/// supplied, call will silently ignore it.
			/// </param>
			/// <param name="enabled">
			/// A bool which sets the enabled state of the supplied option.
			/// </param>
			void SetOptionEnabled(uint32_t option, bool enabled);

			/// <summary>
			/// Checks if the specified filtering category is enabled.
			/// </summary>
			/// <param name="category">
			/// The category, represented by an unsigned 8 bit integer. The underlying Engine is
			/// largely agnostic to the meaning attached to specified values, with the sole
			/// exception being the value zero. Zero is reserved to indicate "Do not filter". Aside
			/// from that, the total number of available categories that the user may employ spans
			/// from one to the upper numeric limits of the unsigned 8 bit integer.
			/// </param>
			/// <returns>
			/// True if the specified filtering category is enabled, false otherwise.
			/// </returns>
			bool IsCategoryEnabled(uint8_t category);

			/// <summary>
			/// Sets whether the supplied filtering category is enabled or not.
			/// </summary>
			/// <param name="category">
			/// The category, represented by an unsigned 8 bit integer. The underlying Engine is
			/// largely agnostic to the meaning attached to specified values, with the sole
			/// exception being the value zero. Zero is reserved to indicate "Do not filter". Aside
			/// from that, the total number of available categories that the user may employ spans
			/// from one to the upper numeric limits of the unsigned 8 bit integer. Supplying a
			/// value of zero here will result in the call being silently ignored.
			/// </param>
			/// <param name="enabled">
			/// A bool which sets the enabled state of the supplied filtering category.
			/// </param>
			void SetCategoryEnabled(uint8_t category, bool enabled);			

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
			delegate bool UnmanagedFirewallCheckCallback(const char* binaryAbsolutePath, const size_t binaryAbsolutePathLength);

			/// <summary>
			/// See notes on UnmanagedFirewallCheckCallback. This is the managed, unmanaged callback
			/// delegate for onInfo, onWarn and onError.
			/// </summary>
			delegate void UnmanagedMessageCallback(const char* message, const size_t messageLength);

			/// <summary>
			/// See notes on UnmanagedFirewallCheckCallback. This is the managed, unmanaged callback
			/// for information about blocked requests.
			/// </summary>
			delegate void UnmanagedReportRequestBlockedCallback(const uint8_t category, const uint32_t payloadSizeBlocked, const char* host, const size_t hostLength);

			/// <summary>
			/// See notes on UnmanagedFirewallCheckCallback. This is the managed, unmanaged callback
			/// for information about HTML elements removed from HTML payloads.
			/// </summary>
			delegate void UnmanagedReportElementsBlockedCallback(const uint32_t numElementsRemoved, const char* fullRequest, const size_t requestLength);					

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
			/// OnRequestBlocked callback to supply to the unmanaged side.
			/// </summary>
			UnmanagedReportRequestBlockedCallback^ m_unmanagedOnRequestBlockedCallback = nullptr;

			/// <summary>
			/// OnElementsBlocked callback to supply to the unmanaged side.
			/// </summary>
			UnmanagedReportElementsBlockedCallback^ m_unmanagedOnElementsBlockedCallback = nullptr;
			
			/// <summary>
			/// Pointer to the unmanaged Engine structure.
			/// </summary>
			PHttpFilteringEngineCtl m_handle = nullptr;

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
			OnFirewallCheckCallback^ m_onFirewallCallback = nullptr;

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

			void UnmanagedOnRequestBlocked(const uint8_t category, const uint32_t payloadSizeBlocked, const char* fullRequest, const size_t requestLength);

			void UnmanagedOnElementsBlocked(const uint32_t numElementsRemoved, const char* fullRequest, const size_t requestLength);

		};

	} /* namespace HttpFilteringEngine */
} /* namespace Te */
