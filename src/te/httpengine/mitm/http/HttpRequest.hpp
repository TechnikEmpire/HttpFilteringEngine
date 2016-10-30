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
				/// The HttpRequest class manages the request side of HTTP transactions. The
				/// request class differs from the HttpResponse class only in providing additional
				/// methods for fetching and manipulating data specific to HTTP requests, such as
				/// the request URI field.
				/// </summary>
				class HttpRequest : public BaseHttpTransaction
				{

				public:

					typedef http_method HttpRequestMethod;

					/// <summary>
					/// Default constructor. Initializes the internal http_parser object which is
					/// used for accurately parsing request headers. The body/payload methods of the
					/// http_parser callbacks are largely ignored, as the HttpResponse already holds
					/// the payoad buffer.
					/// </summary>
					HttpRequest();

					/// <summary>
					/// Constructs a request with the initial given payload. The payload is placed
					/// in the header buffer directly, leaving this object in the same state is if it
					/// had just finished being used to complete its first read from raw socket data.
					/// </summary>
					/// <param name="data">
					/// A valid pointer to the start of the initial payload data.
					/// </param>
					/// <param name="length">
					/// The total length in bytes of the initial payload data
					/// </param>					
					HttpRequest(const char* data, const size_t length);

					/// <summary>
					/// Default destructor. Frees the internal http_parser.
					/// </summary>
					virtual ~HttpRequest();

					/// <summary>
					/// Getter for the URI of the requested resource. 
					/// </summary>
					/// <returns>
					/// The complete URI of the requested resource, if available. May return an
					/// empty string if the state of the request is such that this information has
					/// not been received or parsed.
					/// </returns>
					const std::string& RequestURI() const;

					/// <summary>
					/// Setter for the URI of the requested resource.
					/// </summary>
					/// <param name="value">
					/// The desired URI of the requested resource.
					/// </param>
					void RequestURI(const std::string& value);

					/// <summary>
					/// Getter for the method of the request. 
					/// </summary>
					/// <returns>
					/// The method of the request, if available. Defaults to GET in the event that
					/// the internal state of the request is such that this information has not been
					/// received or parsed.
					/// </returns>
					const HttpRequestMethod Method() const;

					/// <summary>
					/// Setter for the method of the request.
					/// </summary>
					/// <param name="method">
					/// The desired request method.
					/// </param>
					void Method(const HttpRequestMethod method);

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
					/// The URI portion of the HTTP request headers.
					/// </summary>
					std::string m_requestURI;

					/// <summary>
					/// The request method.
					/// </summary>
					HttpRequestMethod m_requestMethod;

					/// <summary>
					/// Called when the url read has been completed by http_parser. 
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
					static int OnUrl(http_parser* parser, const char *at, size_t length);

				};

			} /* namespace http */
		} /* namespace mitm */
	} /* namespace httpengine */
} /* namespace te */