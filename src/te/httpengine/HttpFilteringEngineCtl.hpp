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
	typedef bool(*FirewallCheckCallback)(const char*, size_t);

	/// <summary>
	/// The Engine handles any error that occurs in situations related to external input. This is
	/// because the very nature of the Engine is to deal with unpredictable external input. However,
	/// to prevent some insight and feedback to users, various callbacks are used for errors,
	/// warnings, and general information.
	/// 
	/// When constructing a new instance of the Engine, these callbacks should be provided to the
	/// construction mechanism.
	/// </summary>
	typedef void(*ReportMessageCallback)(const char*, size_t);

	/// <summary>
	/// Creates a new instance of the HttpFilteringEngineCtl class, which manages the operation of
	/// the HTTP Filtering Engine.
	/// </summary>
	/// <param name="cb">
	/// A valid function pointer to a method which will accept a string containing the full path to
	/// a binary that the Engine is considering intercepting and diverting its traffic through
	/// itself. This callback is expected to give permission to intercept the traffic.
	/// </param>
	HTTP_FILTERING_ENGINE_API te::httpengine::HttpFilteringEngineCtl* fe_ctl_create(
		FirewallCheckCallback cb, 
		ReportMessageCallback onError, 
		ReportMessageCallback onWarn, 
		ReportMessageCallback onInfo
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

			HttpFilteringEngineCtl();

			~HttpFilteringEngineCtl();

			void Start();

			void Stop();

			bool IsRunning() const;

		private:

			std::unique_ptr<filtering::http::HttpFilteringEngine> m_httpFilteringEngine;

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
		};

	} /* namespace httpengine */
} /* namespace te */