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

#ifdef __cplusplus
	#include <cstdint>
	#include <functional>
#else
	// XXX TODO What to include for C? 
#endif //#ifdef __cplusplus

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
typedef void(*ReportBlockedRequestCallback)(const uint8_t category, const uint32_t payloadSizeBlocked, const char* fullRequest, const size_t requestLength);

/// <summary>
/// When the Engine removes elements from a specific web page, it will report information about
/// that event, if a callback is provided to do so. This information is simply the number of
/// elements removed and the full request that contained the returned HTML on which the
/// selectors were run. Category information is unfortunately not available, since selectors
/// from all categories are collectively used to remove multiple elements, unlike filters where
/// a single filter is ultimately responsible for blocking or whitelisting a request.
/// </summary>
typedef void(*ReportBlockedElementsCallback)(const uint32_t numElementsRemoved, const char* fullRequest, const size_t requestLength);

#ifdef __cplusplus
namespace te
{
	namespace httpengine
	{
		namespace util
		{
			namespace cb
			{
				
				using FirewallCheckFunction = std::function<bool(const char* binaryAbsolutePath, const size_t binaryAbsolutePathLength)>;
				using MessageFunction = std::function<void(const char* message, const size_t messageLength)>;
				using RequestBlockFunction = std::function<void(const uint8_t category, const uint32_t payloadSizeBlocked, const char* fullRequest, const size_t requestLength)>;
				using ElementBlockFunction = std::function<void(const uint32_t numElementsRemoved, const char* fullRequest, const size_t requestLength)>;
			
			} /* namespace cb */
		} /* namespace util */
	} /* namespace httpengine */
} /* namespace te */
#endif //#ifdef __cplusplus