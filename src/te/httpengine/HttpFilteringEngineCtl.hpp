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

#include <cstdint>
#include <memory>
#include <boost/predef.h>
#include <functional>

// Forward decls to keep implementation away from the interface. This isn't just for improved
// compiler performance, it's absolutely required to prevent the native code from getting gobbled up
// and included for managed compiliation to MSIL when the library is used within .NET.
namespace te
{
	namespace httpengine
	{
		
		class HttpFilteringEngineCtl;

	} /* namespace httpengine */

	namespace filtering
	{
		namespace http
		{

			class HttpFilteringEngine;

		} /* namespace http */
	} /* namespace filtering */

	namespace mitm
	{
		namespace diversion
		{

			class BaseDiverter;

		} /* namespace diversion */
	} /* namespace mitm */

} /* namespace te */


// C API. XXX TODO - Perhaps this should be separated out to another file?
// XXX TODO - This isn't at all suitable for a C project to include, because we
// throw exceptions and such in the exported methods. We need to remove the throws
// and leave the asserts, change the return types on all these methods to return
// error/status codes to indicate just what went wrong in such a situation instead.
// Also this does in fact need to be split into a separate file if we're really 
// wanting to enable use from C, something outside of the scope presently.
#ifdef HTTP_FILTERING_ENGINE_EXPORT
	#if BOOST_OS_WINDOWS
		#ifdef _MSC_VER
			#define HTTP_FILTERING_ENGINE_API __declspec(dllexport)
		#else
			#define HTTP_FILTERING_ENGINE_API __attribute__((visibility("default")))
		#endif // #ifdef _MSC_VER
	#else
		#define HTTP_FILTERING_ENGINE_API __attribute__((visibility("default")))
	#endif	// #if BOOST_OS_WINDOWS
#else
	#if BOOST_OS_WINDOWS
		#ifdef _MSC_VER
			#define HTTP_FILTERING_ENGINE_API __declspec(dllimport)
		#else
			#define HTTP_FILTERING_ENGINE_API
		#endif
	#else
		#define HTTP_FILTERING_ENGINE_API
	#endif	
#endif // #ifdef HTTP_FILTERING_ENGINE_EXPORT

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

	// Woa, major change in coding here. This guy can't even stay consistent with his coding
	// convention. Tsk Tsk, shake head, etc. Even though looking at those thin little underscores
	// are like razor blades sliding across my eyeballs as I scan the screen reading them, some of
	// the names used in the C API are very long. Very long names are the Achilles' heel of camel case.

	/// <summary>
	/// On Windows, at the very least, internet access is controlled by the default firewall
	/// (Windows Firewall) on a per-application basis. We need to be able to query this firewall
	/// whenever we consider intercepting and diverting a new flow through the proxy, to ensure that
	/// we are not just handing out free candy, and by free candy I mean free access to the
	/// internet. I know, free candy made it perfectly clear and I didn't need to explain.
	/// 
	/// This callback must be supplied to a valid function which can give us this information when
	/// creating new instances of the Engine. The burden of correctly implementing this
	/// functionality is on the end-user of this library.
	/// </summary>
	typedef bool(*FirewallCheckCallback)(const char* binaryAbsolutePath, const size_t binaryAbsolutePathLength);

	/// <summary>
	/// The Engine handles any error that occurs in situations related to external input. This is
	/// because the very nature of the Engine is to deal with unpredictable external input. However,
	/// to prevent some insight and feedback to users, various callbacks are used for errors,
	/// warnings, and general information.
	/// 
	/// When constructing a new instance of the Engine, these callbacks should be provided to the
	/// construction mechanism.
	/// </summary>
	typedef void(*ReportMessageCallback)(const char* message, const size_t messageLength);

	/// <summary>
	/// When the Engine blocks a request, it will report information about the blocking event, if a
	/// callback is provided to do so. This information includes the category that the filter
	/// responsible for the block belongs to, the size of the payload which would have been
	/// transferred if the request were not blocked (only if this option is enabled), and the host
	/// of the blocked request.
	/// 
	/// If the filtering option to fetch and report the blocked payload size is disabled or if the
	/// payload is configured to be delivered as a chunked response, the size reported will be zero.
	/// </summary>
	typedef void(*ReportBlockedRequestCallback)(const uint8_t category, const uint32_t payloadSizeBlocked, const char* host, const size_t hostLength);

	/// <summary>
	/// When the Engine removes elements from a specific web page, it will report information about
	/// that event, if a callback is provided to do so. This information is simply the number of
	/// elements removed and the full request that contained the returned HTML on which the
	/// selectors were run. Category information is unfortunately not available, since selectors
	/// from all categories are collectively used to remove multiple elements, unlike filters where
	/// a single filter is ultimately responsible for blocking or whitelisting a request.
	/// </summary>
	typedef void(*ReportBlockedElementsCallback)(const uint32_t numElementsRemoved, const char* fullRequest, const size_t requestLength);

	/// <summary>
	/// Creates a new instance of the HttpFilteringEngineCtl class, which manages the operation of
	/// the HTTP Filtering Engine.
	/// 
	/// It's a little messy having so many defined callbacks required at creation time, but there is
	/// a lot of information that the Engine can report and request, and is also multithreaded in
	/// nearly every aspect. Avoiding incurring the cost of synchronizing callbacks post creation is
	/// the reason for having this design here.
	/// </summary>
	/// <param name="firewallCb">
	/// A pointer to a method that is meant to determine if the supplied absolute binary
	/// path points to a binary that has been approved for internet access.
	/// </param>
	/// <param name="onInfo">
	/// A pointer to a method that can accept string informational data generated by the
	/// underlying Engine. Default is nullptr. This callback cannot be supplied post-construction.
	/// </param>
	/// <param name="onWarn">
	/// A pointer to a method that can accept string warning data generated by the
	/// underlying Engine. Default is nullptr. This callback cannot be supplied post-construction.
	/// </param>
	/// <param name="onError">
	/// A pointer to a method that can accept string error data generated by the underlying
	/// Engine. Default is nullptr. This callback cannot be supplied post-construction.
	/// </param>
	/// <param name="onRequestBlocked">
	/// A pointer to a method that can accept information about blocked requests generated
	/// by the underlying Engine. Default is nullptr. This callback cannot be supplied post-construction.
	/// </param>
	/// <param name="onElementsBlocked">
	/// A pointer to a method that can accept information about HTML elements removed by CSS
	/// selects, generated by the underlying Engine. Default is nullptr. This callback
	/// cannot be supplied post-construction.
	/// </param>
	HTTP_FILTERING_ENGINE_API te::httpengine::HttpFilteringEngineCtl* fe_ctl_create(
		FirewallCheckCallback firewallCb = nullptr,
		ReportMessageCallback onInfo = nullptr,
		ReportMessageCallback onWarn = nullptr,
		ReportMessageCallback onError = nullptr,
		ReportBlockedRequestCallback onRequestBlocked = nullptr,
		ReportBlockedElementsCallback onElementsBlocked = nullptr
		);

	/// <summary>
	/// Destroys an existing Engine instance. If the Engine is running, it will be correctly shut
	/// down. Regardless of its state, the Engine instance pointed to will be destroyed and the
	/// supplied ptr argument will no longer be valid.
	/// </summary>
	/// <param name="ptr">
	/// A valid pointer to an existing Engine instance.
	/// </param>
	HTTP_FILTERING_ENGINE_API void fe_ctl_destroy(te::httpengine::HttpFilteringEngineCtl* ptr);

	/// <summary>
	/// Begins intercepting and diverting HTTP/S traffic through the Engine.
	/// </summary>
	/// <param name="ptr">
	/// A valid pointer to an existing Engine instance.
	/// </param>
	HTTP_FILTERING_ENGINE_API void fe_ctl_start(te::httpengine::HttpFilteringEngineCtl* ptr);

	/// <summary>
	/// Stops intercepting and diverting HTTP/S traffic through the Engine.
	/// </summary>
	/// <param name="ptr">
	/// A valid pointer to an existing Engine instance.
	/// </param>
	HTTP_FILTERING_ENGINE_API void fe_ctl_stop(te::httpengine::HttpFilteringEngineCtl* ptr);

	/// <summary>
	/// Checks if the Engine is actively diverting and filtering HTTP/S traffic or not.
	/// </summary>
	/// <param name="ptr">
	/// A valid pointer to an existing Engine instance.
	/// </param>
	/// <returns>
	/// True if the Engine is actively diverting and filtering HTTP/S traffic, false otherwise.
	/// </returns>
	HTTP_FILTERING_ENGINE_API bool fe_ctl_is_running(te::httpengine::HttpFilteringEngineCtl* ptr);

	/// <summary>
	/// Gets the port that the Engine is listening on for diverted HTTP connections.
	/// </summary>
	/// <param name="ptr">
	/// A valid pointer to an existing Engine instance.
	/// </param>
	/// <returns>
	/// The port the Engine is listening on for diverted HTTP connections.
	/// </returns>
	HTTP_FILTERING_ENGINE_API uint16_t fe_ctl_get_http_listener_port(te::httpengine::HttpFilteringEngineCtl* ptr);

	/// <summary>
	/// Sets the port that the Engine is listening on for diverted HTTP connections. If the Engine
	/// is running when this method is invoked, it must be restarted to see the changes take effect.
	/// </summary>
	/// <param name="ptr">
	/// A valid pointer to an existing Engine instance.
	/// </param>
	/// <param name="val">
	/// The port number on which to listen for diverted HTTP connections.
	/// </param>
	HTTP_FILTERING_ENGINE_API void fe_ctl_set_http_listener_port(te::httpengine::HttpFilteringEngineCtl* ptr, const uint16_t val);

	/// <summary>
	/// Gets the port that the Engine is listening on for diverted HTTPS connections.
	/// </summary>
	/// <param name="ptr">
	/// A valid pointer to an existing Engine instance.
	/// </param>
	/// <returns>
	/// The port the Engine is listening on for diverted HTTPS connections
	/// </returns>
	HTTP_FILTERING_ENGINE_API uint16_t fe_ctl_get_https_listener_port(te::httpengine::HttpFilteringEngineCtl* ptr);

	/// <summary>
	/// Sets the port that the Engine is listening on for diverted HTTPS connections. If the Engine
	/// is running when this method is invoked, it must be restarted to see the changes take effect.
	/// </summary>
	/// <param name="ptr">
	/// A valid pointer to an existing Engine instance.
	/// </param>
	/// <param name="val">
	/// The port number on which to listen for diverted HTTPS connections.
	/// </param>
	HTTP_FILTERING_ENGINE_API void fe_ctl_set_https_listener_port(te::httpengine::HttpFilteringEngineCtl* ptr, const uint16_t val);

	/// <summary>
	/// Checks whether the queried option is enabled in the Engine. Options are specific, and
	/// library users should be provided with enumerations of these options in their respective
	/// languages so ensure correct functionality and clarity of intent for each option. Also, do
	/// not confuse options with categories. Options are preset values which govern specific,
	/// special functionality of the Engine. Categories are any non-zero user defined types that the
	/// Engine only uses to allow users to categorize rules loaded by the user.
	/// </summary>
	/// <param name="ptr">
	/// A valid pointer to an existing Engine instance.
	/// </param>
	/// <param name="optionId">
	/// The ID of the option to query.
	/// </param>
	/// <returns>
	/// True if the option queried is enabled, false otherwise.
	/// </returns>
	HTTP_FILTERING_ENGINE_API bool fe_ctl_get_option(te::httpengine::HttpFilteringEngineCtl* ptr, const uint32_t optionId);

	/// <summary>
	/// Sets whether the queried option is enabled in the Engine or not. Options are specific, and
	/// library users should be provided with enumerations of these options in their respective
	/// languages so ensure correct functionality and clarity of intent for each option. Also, do
	/// not confuse options with categories. Options are preset values which govern specific,
	/// special functionality of the Engine. Categories are any non-zero user defined types that the
	/// Engine only uses to allow users to categorize rules loaded by the user.
	/// </summary>
	/// <param name="ptr">
	/// A valid pointer to an existing Engine instance.
	/// </param>
	/// <param name="optionId">
	/// The ID of the option to change the value of.
	/// </param>
	/// <param name="val">
	/// The value to set for the supplied option.
	/// </param>
	HTTP_FILTERING_ENGINE_API void fe_ctl_set_option(te::httpengine::HttpFilteringEngineCtl* ptr, const uint32_t optionId, const bool val);

	/// <summary>
	/// Sets whether the queried user defined category is enabled in the Engine or not. Categories
	/// are user defined numeric values which the engine is agnostic to the underlying meaning of
	/// specific values. The Engine uses these values to index rules loaded from various lists to
	/// simply provide the user the capability to turn certain lists on and off. The only
	/// restriction is that the user cannot supply a zero value for categories, as this is reserved
	/// by the Engine for the "unfiltered" category.
	/// 
	/// Also, do not confuse options with categories. Options are preset values which govern
	/// specific, special functionality of the Engine. Categories are any non-zero user defined
	/// types that the Engine only uses to allow users to categorize rules loaded by the user.
	/// </summary>
	/// <param name="ptr">
	/// A valid pointer to an existing Engine instance.
	/// </param>
	/// <param name="categoryId">
	/// The ID of the category to query. Must be non-zero. Supplying a zero value for the category
	/// will result in an immediate false return value.
	/// </param>
	/// <returns>
	/// True if the category queried is enabled, false otherwise.
	/// </returns>
	HTTP_FILTERING_ENGINE_API bool fe_ctl_get_category(te::httpengine::HttpFilteringEngineCtl* ptr, const uint8_t categoryId);

	/// <summary>
	/// Gets whether the queried user defined category is enabled in the Engine or not. Categories
	/// are user defined numeric values which the engine is agnostic to the underlying meaning of
	/// specific values. The Engine uses these values to index rules loaded from various lists to
	/// simply provide the user the capability to turn certain lists on and off. The only
	/// restriction is that the user cannot supply a zero value for categories, as this is reserved
	/// by the Engine for the "unfiltered" category.
	/// 
	/// Also, do not confuse options with categories. Options are preset values which govern
	/// specific, special functionality of the Engine. Categories are any non-zero user defined
	/// types that the Engine only uses to allow users to categorize rules loaded by the user.
	/// </summary>
	/// <param name="ptr">
	/// A valid pointer to an existing Engine instance.
	/// </param>
	/// <param name="categoryId">
	/// The ID of the category to change the value of. Must be non-zero. Supplying a zero value for
	/// the category will result in an immediate return, and no change will be made internally.
	/// </param>
	/// <param name="val">
	/// The value to set for the supplied category.
	/// </param>
	HTTP_FILTERING_ENGINE_API void fe_ctl_set_category(te::httpengine::HttpFilteringEngineCtl* ptr, const uint8_t categoryId, const bool val);

	/// <summary>
	/// Attempts to have the Engine load an Adblock Plus formatted list containing filtering and
	/// hiding rules from the filesystem.
	/// </summary>
	/// <param name="ptr">
	/// A valid pointer to an existing Engine instance.
	/// </param>
	/// <param name="filePath">
	/// A pointer to a string containing the absolute path to the file to be loaded.
	/// </param>
	/// <param name="filePathLength">
	/// The total length of the supplied file path string.
	/// </param>
	/// <param name="listCategory">
	/// The category that the rules loaded from the list should be classified as belonging to. This
	/// is entirely user specified and the Engine is **mostly** agnostic to the meaning of these
	/// values. The value zero is reserved to represent the "unfiltered" category. Aside from this,
	/// whatever other value these categories are are has no bearing on internal functionality.
	/// </param>
	/// <returns>
	/// True if the file was successfully loaded and processed without error, false otherwise. Note
	/// that a false return value does not necessarily mean that none of the rules were loaded and
	/// processed correctly. The Engine will return false if there is an issue with even a single
	/// entry within the file, but will continue processing all non-error-throwing rules. The false
	/// return type is to notify the user that there was still an issue. The user can use other
	/// provided interfaces to programmatically investigate the true reason for the false return value.
	/// </returns>
	HTTP_FILTERING_ENGINE_API bool fe_ctl_load_list_from_file(
		te::httpengine::HttpFilteringEngineCtl* ptr, 
		const char* filePath, 
		const size_t filePathLength, 
		const uint8_t listCategory
		);

	/// <summary>
	/// Attempts to have the Engine treat the supplied string as an Adblock Plus formatted list
	/// containing filtering and hiding rules from the filesystem, parsing them from the string.
	/// </summary>
	/// <param name="ptr">
	/// A valid pointer to an existing Engine instance.
	/// </param>
	/// <param name="listString">
	/// A pointer to a string containing the Adblock Plus formatted list of filtering rules.
	/// </param>
	/// <param name="listStringLength">
	/// The total length of the supplied list string.
	/// </param>
	/// <param name="listCategory">
	/// The category that the rules loaded from the list should be classified as belonging to. This
	/// is entirely user specified and the Engine is **mostly** agnostic to the meaning of these
	/// values. The value zero is reserved to represent the "unfiltered" category. Aside from this,
	/// whatever other value these categories are are has no bearing on internal functionality.
	/// </param>
	/// <returns>
	/// True if the supplied string was processed without error, false otherwise. Note that a false
	/// return value does not necessarily mean that none of the rules were loaded and processed
	/// correctly. The Engine will return false if there is an issue with even a single entry within
	/// the file, but will continue processing all non-error-throwing rules. The false return type
	/// is to notify the user that there was still an issue. The user can use other provided
	/// interfaces to programmatically investigate the true reason for the false return value.
	/// </returns>
	HTTP_FILTERING_ENGINE_API bool fe_ctl_load_list_from_string(
		te::httpengine::HttpFilteringEngineCtl* ptr, 
		const char* listString, 
		const size_t listStringLength, 
		const uint8_t listCategory
		);


#ifdef __cplusplus
};
#endif // __cplusplus

namespace te
{
	namespace httpengine
	{

		/// <summary>
		/// The HttpFilteringEngineCtl class is the managing class that employs all other classes in
		/// this Engine to provide the combined functionality of intercepting and diverting HTTP/S
		/// traffic, a transparent proxy listening for handling the traffic for those diverted
		/// clients, and the Http Filtering Engine for inspecting and filtering requests and
		/// response payloads based on user loaded rulesets.
		/// 
		/// One of the platforms supported by this Engine is Windows, where this project is compiled
		/// as a CLR library to be included in and controlled by a WPF C# application. Every single
		/// piece of native code in this library is configured to be compiled WITHOUT CLR support,
		/// with the exception of the single CLR class which provides the glue between the unmanaged
		/// and managed side. As such, this Engine, even in CLR mode, functions as fully native AOT
		/// compiled static code that gets all of the optimization treatment of a standard C++
		/// compiler. However, this doesn't come without a bit of work.
		/// 
		/// To ensure that MSVC can properly provide this clear separation, we have to forward
		/// declare pure native classes that are used in this class, to keep the seperation pure.
		/// That is to say, we don't want any includes here so that when this header is included by
		/// for a CLR project, our underlying data structures remain unmanaged, as the actual
		/// implementation is hidden away in the source, a source file that is marked to have CLR
		/// support disabled explicitly.
		/// 
		/// If we do not, compilation will fail because we include some types which just cannot be
		/// properly included in managed code, such as everything the atomic header brings in. An
		/// even worse fate would be for MSVC to gain managed compatibility with the headers we
		/// include, and silently our beautiful, pure portable C++ code is not getting the tender
		/// loving care of a regular C++ compiler, but is getting compiled to MSIL.
		/// 
		/// So, this abstraction is a bit tedious, but necessary and must be adhered to strictly for
		/// any future additions or maintenance. It is solely this header that is to be included in
		/// the managed side. If any other header from this library needs to ever be included on the
		/// managed side, the same abstraction must be done there also.
		/// </summary>
		class HttpFilteringEngineCtl
		{

		public:

			/// <summary>
			/// Constructs a new HttpFilteringEngineCtl. Requires a valid firewall callback function
			/// pointer on Windows or the constructor will throw. Optionally, callbacks for
			/// information, warning and error events within the underlying Engine can be supplied
			/// as well.
			/// </summary>
			/// <param name="firewallCb">
			/// A pointer to a method that is meant to determine if the supplied absolute binary
			/// path points to a binary that has been approved for internet access.
			/// </param>
			/// <param name="onInfo">
			/// A pointer to a method that can accept string informational data generated by the
			/// underlying Engine. Default is nullptr. This callback cannot be supplied post-construction.
			/// </param>
			/// <param name="onWarn">
			/// A pointer to a method that can accept string warning data generated by the
			/// underlying Engine. Default is nullptr. This callback cannot be supplied post-construction.
			/// </param>
			/// <param name="onError">
			/// A pointer to a method that can accept string error data generated by the underlying
			/// Engine. Default is nullptr. This callback cannot be supplied post-construction.
			/// </param>
			/// <param name="onRequestBlocked">
			/// A pointer to a method that can accept information about blocked requests generated
			/// by the underlying Engine. Default is nullptr. This callback cannot be supplied post-construction.
			/// </param>
			/// <param name="onElementsBlocked">
			/// A pointer to a method that can accept information about HTML elements removed by CSS
			/// selects, generated by the underlying Engine. Default is nullptr. This callback
			/// cannot be supplied post-construction.
			/// </param>
			HttpFilteringEngineCtl(
				FirewallCheckCallback firewallCb = nullptr,
				ReportMessageCallback onInfo = nullptr,
				ReportMessageCallback onWarn = nullptr,
				ReportMessageCallback onError = nullptr,
				ReportBlockedRequestCallback onRequestBlocked = nullptr,
				ReportBlockedElementsCallback onElementsBlocked = nullptr
				);

			/// <summary>
			/// Default destructor.
			/// </summary>
			~HttpFilteringEngineCtl();

			/// <summary>
			/// If the underlying Engine is not running at the time that this method is invoked, the
			/// Engine will begin diverting traffic to itself and listening for incoming diverted
			/// HTTP and HTTPS connections to filter. If the underlying Engine is already running,
			/// the call will have no effect.
			/// </summary>
			void Start();

			/// <summary>
			/// If the underlying Engine is running at the time that this method is invoked, the
			/// Engine will cease diverting traffic to itself and cease listening for incoming
			/// diverted HTTP and HTTPS connections. If the underlying Engine is not running, the
			/// call will have no effect.
			/// </summary>
			void Stop();

			/// <summary>
			/// Checks whether the underlying Engine and its associated mechanisms are presently
			/// diverting traffic to itself and listening for incoming diverted HTTP and HTTPS
			/// connections to filter.
			/// </summary>
			/// <returns>
			/// True if the underlying Engine is actively diverting and receiving HTTP and HTTPS
			/// connections for filtering at the time of the call, false otherwise.
			/// </returns>
			bool IsRunning() const;

		private:

			using FirewallCheckFunction = std::function<bool(const char* binaryAbsolutePath, const size_t binaryAbsolutePathLength)>;
			using MessageFunction = std::function<void(const char* message, const size_t messageLength)>;
			using RequestBlockFunction = std::function<void(const uint8_t category, const uint32_t payloadSizeBlocked, const char* host, const size_t hostLength)>;
			using ElementBlockFunction = std::function<void(const uint32_t numElementsRemoved, const char* fullRequest, const size_t requestLength)>;

			/// <summary>
			/// The underlying filtering Engine responsible for blocking request and removing HTML
			/// elements with CSS selectors.
			/// </summary>
			std::unique_ptr<filtering::http::HttpFilteringEngine> m_httpFilteringEngine;

			/// <summary>
			/// The diversion class that is responsible for diverting HTTP and HTTPS flows to the
			/// HTTP and HTTPS listeners for filtering.
			/// </summary>
			std::unique_ptr<mitm::diversion::BaseDiverter> m_diverter;

			/// <summary>
			/// The true http listener object is templated. We can't fwd that, and we can't include
			/// it with a definition at all because of the compiler firewall between the managed and
			/// umanaged side of this software in the case of .NET being a build target.
			/// </summary>
			struct HttpListenerPimpl;
			std::unique_ptr<HttpListenerPimpl> m_httpListener;

			/// <summary>
			/// The true https listener object is templated. We can't fwd that, and we can't include
			/// it with a definition at all because of the compiler firewall between the managed and
			/// umanaged side of this software in the case of .NET being a build target.
			/// </summary>
			struct HttpsListenerPimpl;
			std::unique_ptr<HttpsListenerPimpl> m_httpListener;	
			
			/// <summary>
			/// If defined, called whenever a packet flow is being considered for diversion to the
			/// proxy, but the binary responsible for sending or receiving the flow has not yet been
			/// identified as a binary permitted to have internet access by the system firewall. If
			/// defined and the return from this callback is true, the binary has permission to
			/// access the internet, and diversion will take place. If false, no diversion will take place.
			/// 
			/// The purpose of this check is to avoid allowing an arbitrary program that would
			/// otherwise be blocked from accessing the internet, to access the internet. Since
			/// intercepted packets are never sent outbound, but rather this software acts as an
			/// agent to fulfill the request(s) itself, an application firewall would not be able to
			/// stop us from bypassing it on behalf of other software, once it has permitted this
			/// software to have internet access.
			/// </summary>
			FirewallCheckFunction m_firewallCheckCb;

			/// <summary>
			/// Any information events generated by the underlying Engine will be sent to this
			/// callback, if defined.
			/// </summary>
			MessageFunction m_onInfoCb;

			/// <summary>
			/// Any warning events generated by the underlying Engine will be sent to this
			/// callback, if defined.
			/// </summary>
			MessageFunction m_onWarnCb;

			/// <summary>
			/// Any error events generated by the underlying Engine will be sent to this
			/// callback, if defined.
			/// </summary>
			MessageFunction m_onErrorCb;

			/// <summary>
			/// If defined, whenever the underlying Engine blocks a request, information about that
			/// event will be send through this callback.
			/// </summary>
			RequestBlockFunction m_onRequestBlockedCb;

			/// <summary>
			/// If defined, whenever the underlying Engine removes HTML elements using CSS
			/// selectors, information about that event will be send through this callback.
			/// </summary>
			ElementBlockFunction m_onElementsBlockedCb;
		};

	} /* namespace httpengine */
} /* namespace te */