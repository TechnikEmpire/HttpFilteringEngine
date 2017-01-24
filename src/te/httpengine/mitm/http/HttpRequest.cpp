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

#include "HttpRequest.hpp"

namespace te
{
	namespace httpengine
	{
		namespace mitm
		{
			namespace http
			{
				HttpRequest::HttpRequest()
				{
					m_httpParserSettings.on_url = &OnUrl;

					// Why do we do this? Apparently, in our tests, sometimes methods that ought not
					// to be called for the type of parser we're using get called, and so if we don't
					// define all of these methods here, then we MAY get a memory access violation
					// resulting in random crashed.
					m_httpParserSettings.on_status = [](http_parser* parser, const char *at, size_t length)->int
					{
						return 0;
					};

					m_httpParser = static_cast<http_parser*>(malloc(sizeof(http_parser)));

					if (m_httpParser == nullptr)
					{
						throw std::runtime_error(u8"In HttpRequest::HttpRequest() - Failed to initialize http_parser.");
					}

					http_parser_init(m_httpParser, HTTP_REQUEST);
					m_httpParser->data = this;
				}

				HttpRequest::HttpRequest(const char* data, const size_t length) : HttpRequest()
				{
					/*
					// Write the data into the header buffer and that's it.
					std::ostream os(&m_headerBuffer);
					os.write(data, length);
					os.flush();
					*/
					std::copy(data, data + length, std::back_inserter(m_buffer));
				}

				HttpRequest::~HttpRequest()
				{

				}

				const std::string& HttpRequest::RequestURI() const
				{
					return m_requestURI;
				}

				void HttpRequest::RequestURI(const std::string& value)
				{
					m_requestURI = value;
				}

				const HttpRequest::HttpRequestMethod HttpRequest::Method() const
				{
					return m_requestMethod;
				}

				void HttpRequest::Method(const HttpRequestMethod method)
				{
					m_requestMethod = method;
				}

				std::string HttpRequest::HeadersToString() const
				{
					std::string ret;

					ret.append(http_method_str(m_requestMethod));
					ret.append(u8" ");

					ret.append(m_requestURI);

					if (m_httpVersion == HttpProtocolVersion::HTTP1)
					{
						ret.append(u8" HTTP/1.0");
					}
					else if (m_httpVersion == HttpProtocolVersion::HTTP1_1)
					{
						ret.append(u8" HTTP/1.1");
					}
					else if (m_httpVersion == HttpProtocolVersion::HTTP2)
					{
						ret.append(u8" HTTP/2.0");
					}

					for (auto header = m_headers.begin(); header != m_headers.end(); ++header)
					{
						ret.append(u8"\r\n").append(header->first).append(u8": ").append(header->second);
					}

					ret.append(u8"\r\n\r\n");

					return ret;
				}

				std::vector<char> HttpRequest::HeadersToVector() const
				{
					std::string headersAsString = HeadersToString();

					return std::vector<char>(headersAsString.begin(), headersAsString.end());
				}

				int HttpRequest::OnUrl(http_parser* parser, const char *at, size_t length)
				{
					if (parser != nullptr)
					{
						HttpRequest* trans = static_cast<HttpRequest*>(parser->data);

						if (trans == nullptr)
						{
							return -1;
						}

						if (parser->http_major == 1)
						{
							if (parser->http_minor == 0)
							{
								trans->m_httpVersion = HttpProtocolVersion::HTTP1;
							}
							else
							{
								// assume 1.1
								trans->m_httpVersion = HttpProtocolVersion::HTTP1_1;
							}
						}
						else if (parser->http_major == 2)
						{
							trans->m_httpVersion = HttpProtocolVersion::HTTP2;
						}
						else
						{
							// assume 1.1
							trans->m_httpVersion = HttpProtocolVersion::HTTP1_1;
						}

						trans->m_requestURI = std::string(at, length);

						trans->m_requestMethod = static_cast<http_method>(parser->method);
						
					}
					else 
					{
						return -1;
					}

					return 0;
				}

			} /* namespace http */
		} /* namespace mitm */
	} /* namespace httpengine */
} /* namespace te */