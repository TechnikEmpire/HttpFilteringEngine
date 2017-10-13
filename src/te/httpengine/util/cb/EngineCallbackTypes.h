/*
* Copyright © 2017 Jesse Nicholson
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

#pragma once

#ifdef __cplusplus
	#include <cstdint>
	#include <functional>
#endif //#ifdef __cplusplus

/// <summary>
/// On Windows, at the very least, internet access is controlled by the default firewall (Windows
/// Firewall) on a per-application basis. We need to be able to query this firewall whenever we
/// consider intercepting and diverting a new flow through the proxy, to ensure that we are not just
/// handing out free candy, and by free candy I mean free access to the internet. I know, free candy
/// made it perfectly clear and I didn't need to explain.
///
/// This callback must be supplied and point to to a valid function which can give us this
/// information when creating new instances of the Engine. The burden of correctly implementing this
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
typedef void(*ReportMessageCallback)(const char* message, const uint32_t messageLength);

typedef void(*CustomResponseStreamWriter)(const char* data, const uint32_t dataLength);

typedef void(*HttpMessageBeginCallback)(
	const char* requestHeaders, const uint32_t requestHeadersLength, const char* requestBody, const uint32_t requestBodyLength, 
	const char* responseHeaders, const uint32_t responseHeadersLength, const char* responseBody, const uint32_t responseBodyLength,
	uint32_t* nextAction, const CustomResponseStreamWriter customBlockResponseStreamWriter
	);

typedef void(*HttpMessageEndCallback)(
	const char* requestHeaders, const uint32_t requestHeadersLength, const char* requestBody, const uint32_t requestBodyLength, 
	const char* responseHeaders, const uint32_t responseHeadersLength, const char* responseBody, const uint32_t responseBodyLength,
	bool* shouldBlock, const CustomResponseStreamWriter customBlockResponseStreamWriter
	);

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

				using HttpMessageBeginCheckFunction = std::function<void(
					const char* requestHeaders, const uint32_t requestHeadersLength, const char* requestBody, const uint32_t requestBodyLength,
					const char* responseHeaders, const uint32_t responseHeadersLength, const char* responseBody, const uint32_t responseBodyLength,
					uint32_t* nextAction, const CustomResponseStreamWriter customBlockResponseStreamWriter
					)>;

				using HttpMessageEndCheckFunction = std::function<void(
					const char* requestHeaders, const uint32_t requestHeadersLength, const char* requestBody, const uint32_t requestBodyLength,
					const char* responseHeaders, const uint32_t responseHeadersLength, const char* responseBody, const uint32_t responseBodyLength,
					bool* shouldBlock, const CustomResponseStreamWriter customBlockResponseStreamWriter
					)>;

			} /* namespace cb */
		} /* namespace util */
	} /* namespace httpengine */
} /* namespace te */
#endif //#ifdef __cplusplus