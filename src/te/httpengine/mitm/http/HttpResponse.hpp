/*
* Copyright © 2017 Jesse Nicholson
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

#pragma once

#include "BaseHttpTransaction.hpp"

namespace te
{
	namespace httpengine
	{
		namespace mitm
		{
			namespace http
			{

				/// <summary>
				/// The HttpResponse class manages the response side of HTTP transactions. The
				/// response class differs from the HttpRequest class only in providing additional
				/// methods for fetching and manipulating data specific to HTTP responses, such as
				/// the status code of the response.
				/// </summary>
				class HttpResponse : public BaseHttpTransaction
				{

				public:

					/// <summary>
					/// Default constructor. Initializes the internal http_parser object which is
					/// used for accurately parsing request headers. The body/payload methods of the
					/// http_parser callbacks are largely ignored, as the HttpResponse already holds
					/// the payoad buffer.
					/// </summary>
					HttpResponse();

					/// <summary>
					/// Constructs a response with the initial given payload. The payload is placed
					/// in the header buffer directly, leaving this object in the same state is if it
					/// had just finished being used to complete its first read from raw socket data.
					/// </summary>
					/// <param name="data">
					/// A valid pointer to the start of the initial payload data.
					/// </param>
					/// <param name="length">
					/// The total length in bytes of the initial payload data
					/// </param>
					HttpResponse(const char* data, const size_t length);

					/// <summary>
					/// Default destructor. Frees the internal http_parser.
					/// </summary>
					virtual ~HttpResponse();

					/// <summary>
					/// Gets the status code of the response. 
					/// </summary>
					/// <returns>
					/// The status code of the response, if available. May return a zero value,
					/// which simply indicates that the status has not been extracted from any
					/// transaction headers.
					/// </returns>
					const uint16_t StatusCode() const;

					/// <summary>
					/// Sets the status code of the response. Setting the status code also
					/// internally sets the correct status message string. As such, passing an
					/// invalid status code will result in undefined behaviour, which will most
					/// likely result in a broken and failed transaction. Originally, throwing an
					/// exception was considered, however, given the known cases where even large
					/// companies decide to invent their own status codes and messages (like twitter
					/// 420 Enhance Your Calm for limiting clients making too many requests), the
					/// idea of throwing exceptions was abandoned, thus allowing the user to make
					/// changes which may or may not result in bugs.
					/// 
					/// Because this is a convenience function for avoiding having to correctly
					/// write out standard-defined status codes, please do not use this method for
					/// injecting your own extra special hipster status codes. If you must, do so
					/// using the StatusString(std::string&) method, ensuring that you include code
					/// and message proper, as well as the correct HTTP version (if this doesn't 
					/// already seem like a bad idea, it should start to now).
					/// </summary>
					/// <param name="code">
					/// The standard-defined, valid HTTP status code to set for the response. 
					/// </param>
					void StatusCode(const uint16_t code);

					/// <summary> 
					/// The status string for the response. Note that while a setter
					/// method is provided, one should use StatusCode(const uint16_t&) to minimize
					/// the risk of user mistakes such as mismatching descriptions to codes, typeos,
					/// etc.
					/// 
					/// StatusCode(const uint16_t&) automatically internally sets this string to the
					/// correct value based on the provided code, if the code is legal. 
					/// </summary>
					/// <returns> 
					/// The full status string, including the string representation of the
					/// HTTP status code. 
					/// </returns>
					const std::string& StatusString() const;

					/// <summary> 
					/// Setter to manually build the status code of the response. It is
					/// not advised to use this, but rather to use StatusCode(const uint16_t&), as
					/// it is designed both for convenience and to ensure that the string is
					/// entirely built correctly based on the known HTTP protocol version, the
					/// proper message associated with the code, etc. 
					/// 
					/// Use only if you're a hipster and well defined HTTP status codes are too
					/// mainstream for you. Use at your own risk, etc.
					/// </summary> 
					/// <param name="status">
					/// The complete status message for the response.
					/// </param>
					void StatusString(const std::string& status);

					/// <summary>
					/// Convenience function for formatting the transaction headers into a
					/// std::string container.
					/// </summary>
					/// <returns>
					/// std::string populated with the complete, formatted transaction 
					/// headers.
					/// </returns>
					virtual std::string HeadersToString() const;

					/// <summary> 
					/// Convenience function for formatting the transaction headers into a
					/// std::vector char container. 
					/// </summary> 
					/// <returns> 
					/// std::vector char populated with the complete formatted transaction 
					/// headers. 
					/// </returns>
					virtual std::vector<char> HeadersToVector() const;

				protected:

					/// <summary>
					/// The status code for the response.
					/// </summary>
					uint16_t m_statusCode;

					/// <summary>
					/// The status string for the response. Note that this contains the full status
					/// message, including the code in string format.
					/// </summary>
					std::string m_statusString;

					/// <summary>
					/// Called when the status read been completed by the http_parser.
					/// </summary>
					/// <param name="parser">
					/// The http_parser, returned in the callback for establishing context, since
					/// the callback is static. A pointer to the transaction object is held in
					/// parser->data.
					/// </param>
					/// <param name="at">
					/// A pointer to the position in the data buffer where the data begins. 
					/// </param>
					/// <param name="length">
					/// The length of the data in the buffer. 
					/// </param>
					/// <returns>
					/// The parsing status determined within the callback. Callbacks must return 0
					/// on success. Returning a non-zero value indicates error to the parser, making
					/// it exit immediately.
					/// </returns>
					static int OnStatus(http_parser* parser, const char *at, size_t length);

					/// <summary>
					/// Method for interally constructing the entire status code string, based on
					/// the supplied status code.
					/// </summary>
					/// <param name="code">
					/// The legal/defined HTTP Status Code. 
					/// </param>
					/// <returns>
					/// The string message description to accompany the Http Status Code. 
					/// </returns>
					std::string StatusCodeToMessage(const uint16_t& code) const;

				};

			} /* namespace http */
		} /* namespace mitm */
	} /* namespace httpengine */
} /* namespace te */