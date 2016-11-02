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

#include <sstream>
#include <string>
#include <stdexcept>
#include <utility>
#include <algorithm>
#include <chrono>
#include <boost/algorithm/string.hpp>
#include <boost/iostreams/filtering_stream.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <boost/iostreams/filter/zlib.hpp>
#include <boost/iostreams/copy.hpp>
#include "BaseHttpTransaction.hpp"
#include "../../../util/http/KnownHttpHeaders.hpp"
#include <stdexcept>


namespace te
{
	namespace httpengine
	{
		namespace mitm
		{
			namespace http
			{

				const boost::string_ref BaseHttpTransaction::ContentTypeText = u8"text/";

				const boost::string_ref BaseHttpTransaction::ContentTypeHtml = u8"html";

				const boost::string_ref BaseHttpTransaction::ContentTypeJson = u8"json";

				const boost::string_ref BaseHttpTransaction::ContentTypeImage = u8"image/";

				const boost::string_ref BaseHttpTransaction::ContentTypeCss = u8"css";

				const boost::string_ref BaseHttpTransaction::ContentTypeJavascript = u8"javascript";

				BaseHttpTransaction::BaseHttpTransaction() 
					: 
					m_headerBuffer(MaxPayloadResize)
				{					
					m_httpParserSettings.on_body = &OnBody;
					m_httpParserSettings.on_chunk_complete = &OnChunkComplete;
					m_httpParserSettings.on_chunk_header = &OnChunkHeader;
					m_httpParserSettings.on_headers_complete = &OnHeadersComplete;
					m_httpParserSettings.on_header_field = &OnHeaderField;
					m_httpParserSettings.on_header_value = &OnHeaderValue;
					m_httpParserSettings.on_message_begin = &OnMessageBegin;
					m_httpParserSettings.on_message_complete = &OnMessageComplete;
				}

				BaseHttpTransaction::~BaseHttpTransaction()
				{
					if (m_httpParser != nullptr)
					{
						free(m_httpParser);
					}
				}

				const HttpProtocolVersion BaseHttpTransaction::GetHttpVersion() const
				{
					return m_httpVersion;
				}

				void BaseHttpTransaction::SetHttpVersion(const HttpProtocolVersion httpVersion)
				{
					m_httpVersion = httpVersion;
				}

				void BaseHttpTransaction::AddHeader(const std::string& name, std::string value, const bool replaceIfExists)
				{
					std::string headerNameCopy = name;

					auto matchRange = m_headers.equal_range(headerNameCopy);

					if (replaceIfExists)
					{
						// Since replaceIfExists is true, we want to remove all headers that have the same
						// name before inserting the new header value.
						while (matchRange.first != matchRange.second)
						{
							m_headers.erase(matchRange.first++);
						}

						m_headers.insert(std::make_pair(headerNameCopy, value));

						return;
					}
					else
					{
						auto it = matchRange.first;
						while (it != matchRange.second)
						{
							// If the exact same header and value exist, we clearly don't want to add
							// another.
							if (boost::iequals(it->second, value))
							{
								//Exists already, both name and value
								return;
							}

							++it;
						}

						m_headers.insert(std::make_pair(headerNameCopy, value));
					}
				}

				void BaseHttpTransaction::RemoveHeader(const std::string& name, const std::string& value)
				{
					auto matchRange = m_headers.equal_range(name);

					while (matchRange.first != matchRange.second)
					{
						// Must match exactly both key and value to qualify for removal
						if (boost::iequals(matchRange.first->second.c_str(), value.c_str()))
						{
							m_headers.erase(matchRange.first++);
						}
					}
				}

				void BaseHttpTransaction::RemoveHeader(const std::string& name)
				{
					auto matchRange = m_headers.equal_range(name);

					while (matchRange.first != matchRange.second)
					{
						m_headers.erase(matchRange.first++);
					}
				}

				const HttpHeaderRangeMatch BaseHttpTransaction::GetHeader(const std::string& header) const
				{					
					return m_headers.equal_range(header);
				}

				const bool BaseHttpTransaction::HeadersComplete() const
				{
					return m_headersComplete;
				}

				const bool BaseHttpTransaction::Parse(const size_t bytesReceived)
				{
					bool success = false;

					if (!m_consumeAllBeforeSending)
					{
						// When we're not filling the buffer over potentially multiple reads, just
						// clear it out every single time we're called to parse.
						m_parsedTransactionData.clear();						
					}

					// We reserve at minimum the same amount of data we got here, so that when we're
					// copying out body data in the parser callbacks, we're not getting hammered with
					// re-allocations.
					m_parsedTransactionData.reserve(m_parsedTransactionData.size() + bytesReceived);

					if (!m_headersComplete)
					{	
						std::string hdrString{ (std::istreambuf_iterator<char>(&m_headerBuffer)), std::istreambuf_iterator<char>() };

						// Pull server requests for HTTP2 upgrade
						if (hdrString.size() > 0)
						{
							auto http2 = boost::string_ref(u8"Upgrade: h2\r\n");
							auto http2c = boost::string_ref(u8"Upgrade: h2c\r\n");
							
							boost::erase_all(hdrString, http2);
							boost::erase_all(hdrString, http2c);
						}
						//

						// Because boost::asio lies to us and reads more data into the header buffer than just headers, we cannot
						// rely on the bytesReceived value here. We must look at the whole buffer.
						auto bytesToParse = hdrString.size();

						// The parser must ALWAYS be called first. The OnMessageBegin callback will reset the state
						// of this object, clearing everything excluding the payload data.
						auto nparsed = http_parser_execute(m_httpParser, &m_httpParserSettings, hdrString.c_str(), bytesToParse);

						if (m_httpParser->http_errno != 0)
						{	
							std::string errMsg(u8"In BaseHttpTransaction::Parse(const size_t&) - Failed to parse headers. Got http_parser error: ");
							errMsg.append(http_errno_description(HTTP_PARSER_ERRNO(m_httpParser)));
							ReportError(errMsg);
							ReportInfo(hdrString);
							return false;
						}

						if (m_httpParser->upgrade == 1)
						{		
							ReportError(u8"In BaseHttpTransaction::Parse(const size_t&) - Upgrade requested. Unsupported.");
							ReportInfo(hdrString);
							return false;							
						}

						if (nparsed != bytesToParse)
						{
							ReportError(u8"In BaseHttpTransaction::Parse(const size_t&) - Not all bytes were parsed. Unknown error occurred.");
							ReportInfo(hdrString);
							return false;
						}

						success = true;
					}
					else 
					{	
						auto nparsed = http_parser_execute(m_httpParser, &m_httpParserSettings, m_payloadBuffer.data(), bytesReceived);
						
						if (m_httpParser->upgrade == 1)
						{
							ReportError(u8"In BaseHttpTransaction::Parse(const size_t&) - Upgrade requested. Unsupported.");							
							return false;
						}

						if (m_httpParser->http_errno != 0)
						{
							std::string errMsg(u8"In BaseHttpTransaction::Parse(const size_t&) - Failed to parse payload. Got http_parser error: ");
							errMsg.append(http_errno_description(HTTP_PARSER_ERRNO(m_httpParser)));
							ReportError(errMsg);
							return false;
						}

						if (nparsed != bytesReceived)
						{
							ReportError(u8"In BaseHttpTransaction::Parse(const size_t&) - Not all bytes were parsed. Unknown error occurred.");							
							return false;
						}

						if (nparsed != bytesReceived)
						{
							ReportError(u8"In BaseHttpTransaction::Parse(const size_t&) - Not all bytes were parsed. Unknown error occurred.");							
							return false;
						}
					}

					// If the body is complete, then we need to provide some things which are guaranteed, such as
					// automatic decompression when ::ConsumeAllBeforeSending() is true, and automatic conversion
					// of chunked transfers to fixed-length/precalculated (content-length header defined) transfers.
					if (m_payloadComplete && m_consumeAllBeforeSending)
					{	
						if (IsPayloadCompressed())
						{
							// If the payload is compressed, this will handle correctly decompressing and
							// setting the Content-Length correctly.
							if (!DecompressPayload())
							{
								return false;
							}

							success = true;
						}
						else
						{
							// If not compressed, then we need to ensure there are no transfer-encoding headers,
							// because the parser handles this transparently, and then make sure we update our
							// content-length header.
							RemoveHeader(util::http::headers::TransferEncoding);
							RemoveHeader(util::http::headers::ContentEncoding);
							RemoveHeader(util::http::headers::ContentLength);
							std::string length = std::to_string(m_parsedTransactionData.size());
							AddHeader(util::http::headers::ContentLength, length);

							success = true;
						}
					}
					else
					{
						success = true;
					}

					return success;
				}

				boost::asio::streambuf& BaseHttpTransaction::GetHeaderReadBuffer()
				{
					if (m_headerBuffer.size() > 0)
					{
						// Ensure all data already in the buffer is cleared before initiating
						// a new read.
						m_headerBuffer.consume(m_headerBuffer.size() + 1);
					}

					return m_headerBuffer;
				}

				boost::asio::mutable_buffers_1 BaseHttpTransaction::GetPayloadReadBuffer()
				{
					if (m_payloadBuffer.size() < PayloadBufferReadSize)
					{
						m_payloadBuffer.resize(PayloadBufferReadSize);
					}

					return boost::asio::mutable_buffers_1(m_payloadBuffer.data(), m_payloadBuffer.size());
				}

				boost::asio::const_buffers_1 BaseHttpTransaction::GetWriteBuffer()
				{
					if (!m_headersSent)
					{
						auto headersVector = HeadersToVector();				
						auto newSize = headersVector.size() + m_parsedTransactionData.size();
						headersVector.reserve(newSize);

						if (m_parsedTransactionData.size() > 0)
						{
							headersVector.insert(headersVector.end(), m_parsedTransactionData.begin(), m_parsedTransactionData.end());
						}

						m_parsedTransactionData = std::move(headersVector);

						m_headersSent = true;
					}			

					return boost::asio::const_buffers_1(m_parsedTransactionData.data(), m_parsedTransactionData.size());
				}

				const std::vector<char>& BaseHttpTransaction::GetPayload() const
				{
					return m_parsedTransactionData;
				}

				void BaseHttpTransaction::SetPayload(std::vector<char>&& payload)
				{
					// XXX TODO - Cleanup this code duplication.

					m_parsedTransactionData = std::move(payload);
					m_payloadComplete = true;
										
					RemoveHeader(util::http::headers::ContentLength);
					RemoveHeader(util::http::headers::TransferEncoding);
					RemoveHeader(util::http::headers::ContentEncoding);					

					std::string length = std::to_string(m_parsedTransactionData.size());

					RemoveHeader(util::http::headers::ContentLength);
					AddHeader(util::http::headers::ContentLength, length);
				}

				void BaseHttpTransaction::SetPayload(const std::vector<char>& payload)
				{
					// XXX TODO - Cleanup this code duplication.

					m_parsedTransactionData = payload;
					m_payloadComplete = true;

					RemoveHeader(util::http::headers::ContentLength);
					RemoveHeader(util::http::headers::TransferEncoding);
					RemoveHeader(util::http::headers::ContentEncoding);

					std::string length = std::to_string(m_parsedTransactionData.size());

					RemoveHeader(util::http::headers::ContentLength);
					AddHeader(util::http::headers::ContentLength, length);
				}

				const bool BaseHttpTransaction::IsPayloadComplete() const
				{
					return m_payloadComplete;
				}

				const uint8_t BaseHttpTransaction::GetShouldBlock() const
				{
					return m_shouldBlock;
				}

				void BaseHttpTransaction::SetShouldBlock(const uint8_t category)
				{
					m_shouldBlock = category;

					if (category > 0)
					{
						m_payloadComplete = true;
					}					
				}

				void BaseHttpTransaction::Make204()
				{
					std::stringstream os;

					os << u8"HTTP/"; 

					switch (m_httpVersion)
					{

					case HttpProtocolVersion::HTTP1:
						os << u8"1.0";
						break;
					case HttpProtocolVersion::HTTP1_1:
						os << u8"1.1";
						break;
					case HttpProtocolVersion::HTTP2:
						os << u8"2.0";
						break;

						default:
							os << u8"1.1";
					}

					os << u8" 204 No Content\r\nDate: ";

					std::chrono::time_point<std::chrono::system_clock> now = std::chrono::system_clock::now();
					std::time_t now_t = std::chrono::system_clock::to_time_t(now);
					os << std::ctime(&now_t);
					os << u8"\r\nExpires: ";
					std::chrono::system_clock::time_point epoch;
					std::time_t epoch_t = std::chrono::system_clock::to_time_t(epoch);
					os << std::ctime(&epoch_t);
					os << u8"\r\nContent-Length: 0\r\n\r\n";

					std::string fs = os.str();

					m_parsedTransactionData.clear();

					m_parsedTransactionData.assign(fs.begin(), fs.end());
					m_headersSent = true;
					m_headersComplete = true;
					m_payloadComplete = true;
				}

				const bool BaseHttpTransaction::GetConsumeAllBeforeSending() const
				{
					return m_consumeAllBeforeSending;
				}

				void BaseHttpTransaction::SetConsumeAllBeforeSending(const bool value)
				{
					m_consumeAllBeforeSending = value;
				}

				

				const bool BaseHttpTransaction::IsPayloadChunked() const
				{
					const auto contentEncoding = GetHeader(util::http::headers::TransferEncoding);

					if (contentEncoding.first != contentEncoding.second)
					{
						return true;
					}

					return false;
				}

				const bool BaseHttpTransaction::IsPayloadCompressed() const
				{
					const auto contentEncoding = GetHeader(util::http::headers::ContentEncoding);

					if (contentEncoding.first != contentEncoding.second)
					{
						return true;
					}

					return false;
				}

				const bool BaseHttpTransaction::IsPayloadJson() const
				{
					return DoesContentTypeContain(ContentTypeJson);
				}

				const bool BaseHttpTransaction::IsPayloadHtml() const
				{
					return DoesContentTypeContain(ContentTypeHtml);
				}

				const bool BaseHttpTransaction::IsPayloadText() const
				{
					// We treat JSON, HTML, text/ as text as well.
					if (DoesContentTypeContain(ContentTypeText))
					{
						return true;
					}
					else if (DoesContentTypeContain(ContentTypeHtml))
					{
						return true;
					}
					else if(DoesContentTypeContain(ContentTypeJson))
					{
						return true;
					}

					return false;
				}

				const bool BaseHttpTransaction::IsPayloadImage() const
				{
					return DoesContentTypeContain(ContentTypeImage);
				}

				const bool BaseHttpTransaction::IsPayloadCss() const
				{
					return DoesContentTypeContain(ContentTypeCss);
				}

				const bool BaseHttpTransaction::IsPayloadJavascript() const
				{
					return DoesContentTypeContain(ContentTypeJavascript);
				}

				const bool BaseHttpTransaction::DoesContentTypeMatch(const boost::string_ref type) const
				{
					auto contentTypeHeader = GetHeader(util::http::headers::ContentType);

					if (contentTypeHeader.first != contentTypeHeader.second)
					{
						while (contentTypeHeader.first != contentTypeHeader.second)
						{							
							if (boost::iequals(contentTypeHeader.first->second, type))
							{
								return true;
							}

							contentTypeHeader.first++;
						}
					}
					
					return false;
				}

				const bool BaseHttpTransaction::DoesContentTypeContain(const boost::string_ref type) const
				{
					auto contentTypeHeader = GetHeader(util::http::headers::ContentType);

					while (contentTypeHeader.first != contentTypeHeader.second)
					{
						auto result = boost::ifind_first(contentTypeHeader.first->second, type);
						
						if (!result.empty())
						{
							return true;
						}

						contentTypeHeader.first++;
					}

					return false;
				}

				const bool BaseHttpTransaction::CompressGzip()
				{
					if (m_parsedTransactionData.size() == 0)
					{
						ReportError(u8"In BaseBridge::CompressDeflate() - There is no payload to compress.");
						return false;
					}

					std::vector<char> compressed;

					try
					{
						boost::iostreams::filtering_ostream os;

						os.push(boost::iostreams::gzip_compressor());
						os.push(boost::iostreams::back_inserter(compressed));

						boost::iostreams::write(os, m_parsedTransactionData.data(), m_parsedTransactionData.size());						
					}
					catch (std::exception &e)
					{
						std::string errMessage("In BaseBridge::CompressGzip() - Exception while compressing: ");
						errMessage.append(e.what());
						ReportError(errMessage);
						return false;
					}

					SetPayload(compressed);

					// Must re-add encoding header AFTER calling SetPayload, because it removes such headers.
					std::string gzip(u8"gzip");
					RemoveHeader(util::http::headers::ContentEncoding);
					AddHeader(util::http::headers::ContentEncoding, gzip);
					return true;
				}

				const bool BaseHttpTransaction::CompressDeflate()
				{
					if (m_parsedTransactionData.size() == 0)
					{
						ReportError(u8"In BaseBridge::CompressDeflate() - There is no payload to compress.");
						return false;
					}

					std::vector<char> compressed;

					try
					{
						boost::iostreams::filtering_ostream os;

						os.push(boost::iostreams::zlib_compressor());
						os.push(boost::iostreams::back_inserter(compressed));

						boost::iostreams::write(os, m_parsedTransactionData.data(), m_parsedTransactionData.size());
					}
					catch (std::exception &e)
					{
						std::string errMessage("In BaseBridge::CompressDeflate() - Exception while compressing: ");
						errMessage.append(e.what());
						ReportError(errMessage);
						return false;
					}

					SetPayload(compressed);

					// Must re-add encoding header AFTER calling SetPayload, because it removes such headers.
					std::string deflate(u8"deflate");
					RemoveHeader(util::http::headers::ContentEncoding);
					AddHeader(util::http::headers::ContentEncoding, deflate);
					return true;
				}

				const bool BaseHttpTransaction::DecompressPayload()
				{
					if (!IsPayloadComplete())
					{
						// Can't decompress incomplete buffer.
						return false;
					}

					if (!IsPayloadCompressed())
					{
						// Already decompressed, so we've succeeded.
						return true;
					}

					std::string gzipEnc(u8"gzip");
					std::string deflateEnc(u8"deflate");

					std::string detectedEncoding;					

					const auto contentEncoding = GetHeader(util::http::headers::ContentEncoding);

					if (contentEncoding.first != contentEncoding.second)
					{
						if (boost::iequals(contentEncoding.first->second, gzipEnc))
						{
							detectedEncoding = gzipEnc;
						}
						else if (boost::iequals(contentEncoding.first->second, deflateEnc))
						{
							detectedEncoding = deflateEnc;
						}
						else
						{
							ReportError("In BaseHttpTransaction::DecompressPayload() - Unknown Content-Encoding, cannot decompress: " + contentEncoding.first->second);
							return false;							
						}
					}

					if (detectedEncoding.size() == 0)
					{
						// Count not determine content encoding for decompression.
						ReportError("In BaseHttpTransaction::DecompressPayload() - Count not determine content encoding for decompression.");
						return false;
					}

					if (boost::iequals(detectedEncoding, deflateEnc))
					{
						// Decompress deflate.
						if (!DecompressDeflate())
						{						
							ReportError("In BaseHttpTransaction::DecompressPayload() - Failed to decompress Deflate encoded payload!");
							return false;							
						}
						else
						{
							RemoveHeader(util::http::headers::ContentEncoding);
							RemoveHeader(util::http::headers::TransferEncoding);
							return true;
						}
					}
					else
					{
						// Decompress gzip.
						if (!DecompressGzip())
						{
							ReportError("In BaseHttpTransaction::DecompressPayload() - Failed to decompress Gzip encoded payload!");
							return false;							
						}
						else
						{
							RemoveHeader(util::http::headers::ContentEncoding);
							RemoveHeader(util::http::headers::TransferEncoding);
							return true;
						}
					}

					return false;
				}

				const bool BaseHttpTransaction::DecompressGzip()
				{
					if (m_parsedTransactionData.size() == 0)
					{
						ReportError(u8"In BaseBridge::DecompressGzip() - There is no payload to decompress.");
						return false;
					}

					std::vector<char> decompressed;
					decompressed.reserve(m_parsedTransactionData.size());

					try
					{
						// For some reason, all the example code that boost gives, and all the examples
						// you'll find of "this works" in terms of using boost::asio::gzip streams do
						// not function correctly here. This code does.
						boost::iostreams::back_insert_device< std::vector<char> > decompressorSnk(decompressed);
						boost::iostreams::gzip_decompressor decomp(boost::iostreams::zlib::default_window_bits);
						decomp.write(decompressorSnk, reinterpret_cast<const char*>(&m_parsedTransactionData[0]), m_parsedTransactionData.size());
					}
					catch (std::exception& e)
					{
						std::string errMessage(u8"In BaseBridge::DecompressGzip() - Exception while decompressing: ");
						errMessage.append(e.what());
						ReportError(errMessage);
						return false;
					}					

					// We used to treat zero-sized output as an error. This was wrong. Compressed bytes might come in
					// that hold no actual value when decompressed, but they do have some size/value in compressed
					// format. My guess here is that it's header information wrapping an empty/null value, so when
					// it comes out the other side, it's empty, but valid.
					//
					// By changing this assumption and simply permitting zero-byte outputs, we no longer get
					// mysterious errors about failed decompression or bad requests. It's perfectly legal I guess
					// for a 302 response, for example, to declare chunked encoding, and send an empty gzip payload
					// that when decompressed is nothing.
					SetPayload(std::move(decompressed));
					return true;
				}

				const bool BaseHttpTransaction::DecompressDeflate()
				{
					if (m_parsedTransactionData.size() == 0)
					{
						ReportError(u8"In BaseBridge::DecompressDeflate() - There is no payload to decompress.");
						return false;
					}

					std::vector<char> decompressed;
					decompressed.reserve(m_parsedTransactionData.size());

					try
					{
						// For some reason, all the example code that boost gives, and all the examples
						// you'll find of "this works" in terms of using boost::asio::gzip streams do
						// not function correctly here. This code does.
						boost::iostreams::back_insert_device< std::vector<char> > decompressorSnk(decompressed);
						boost::iostreams::zlib_decompressor decomp(boost::iostreams::zlib::default_window_bits);
						decomp.write(decompressorSnk, reinterpret_cast<const char*>(&m_parsedTransactionData[0]), m_parsedTransactionData.size());
					}
					catch (std::exception& e)
					{
						std::string errMessage(u8"In BaseBridge::DecompressDeflate() - Exception while decompressing: ");
						errMessage.append(e.what());
						ReportError(errMessage);
						return false;
					}

					// We used to treat zero-sized output as an error. This was wrong. Compressed bytes might come in
					// that hold no actual value when decompressed, but they do have some size/value in compressed
					// format. My guess here is that it's header information wrapping an empty/null value, so when
					// it comes out the other side, it's empty, but valid.
					//
					// By changing this assumption and simply permitting zero-byte outputs, we no longer get
					// mysterious errors about failed decompression or bad requests. It's perfectly legal I guess
					// for a 302 response, for example, to declare chunked encoding, and send an empty gzip payload
					// that when decompressed is nothing.
					SetPayload(std::move(decompressed));
					return true;
				}
			
				int BaseHttpTransaction::OnMessageBegin(http_parser* parser)
				{
					if (parser != nullptr)
					{
						BaseHttpTransaction* trans = static_cast<BaseHttpTransaction*>(parser->data);

						if (trans == nullptr)
						{
							throw std::runtime_error(u8"In BaseHttpTransaction::OnMessageBegin() - http_parser->data is nullptr when it should contain a pointer the http_parser's owning BaseHttpTransaction object.");
						}
						
						trans->m_payloadComplete = false;						
						trans->m_consumeAllBeforeSending = false;
						trans->m_shouldBlock = 0;
						trans->m_headers.clear();						
						trans->m_headersSent = false;
						trans->m_headersComplete = false;
						trans->m_lastHeader = std::string("");
						
					}
					else
					{
						throw std::runtime_error(u8"In BaseHttpTransaction::OnMessageBegin() - http_parser is nullptr, somehow. \
							This should never be allowed to happen ever because this apparently null object is supposed to be invoking \
							this callback, but if you're reading this, somehow it did. Welcome to the twilight zone. Nobody can wag \
							their finger at me for not wrapping a raw pointer with a null check.");
					}

					return 0;
				}

				int BaseHttpTransaction::OnHeadersComplete(http_parser* parser)
				{
					if (parser != nullptr)
					{
						BaseHttpTransaction* trans = static_cast<BaseHttpTransaction*>(parser->data);

						if (trans == nullptr)
						{
							throw std::runtime_error(u8"In BaseHttpTransaction::OnHeadersComplete() - http_parser->data is nullptr when it should contain a pointer the http_parser's owning BaseHttpTransaction object.");
						}

						trans->m_headersComplete = true;
						trans->m_headersSent = false;

					}
					else
					{
						throw std::runtime_error(u8"In BaseHttpTransaction::OnHeadersComplete() - - http_parser is nullptr, somehow. \
							This should never be allowed to happen ever because this apparently null object is supposed to be invoking \
							this callback, but if you're reading this, somehow it did. Welcome to the twilight zone. Nobody can wag \
							their finger at me for not wrapping a raw pointer with a null check.");
					}

					return 0;
				}

				int BaseHttpTransaction::OnMessageComplete(http_parser* parser)
				{
					if (parser != nullptr)
					{
						BaseHttpTransaction* trans = static_cast<BaseHttpTransaction*>(parser->data);

						if (trans == nullptr)
						{
							throw std::runtime_error(u8"In BaseHttpTransaction::OnMessageComplete() - http_parser->data is nullptr when it should contain a pointer the http_parser's owning BaseHttpTransaction object.");
						}

						trans->m_payloadComplete = true;
					
					}
					else
					{
						throw std::runtime_error(u8"In BaseHttpTransaction::OnMessageComplete() - http_parser is nullptr, somehow. \
							This should never be allowed to happen ever because this apparently null object is supposed to be invoking \
							this callback, but if you're reading this, somehow it did. Welcome to the twilight zone. Nobody can wag \
							their finger at me for not wrapping a raw pointer with a null check.");
					}

					return 0;
				}

				int BaseHttpTransaction::OnChunkHeader(http_parser* parser)
				{
					// When on_chunk_header is called, the current chunk length is stored
					// in parser->content_length.

					if (parser != nullptr)
					{
						BaseHttpTransaction* trans = static_cast<BaseHttpTransaction*>(parser->data);

						if (trans == nullptr)
						{
							throw std::runtime_error(u8"In BaseHttpTransaction::OnChunkHeader() - http_parser->data is nullptr when it should contain a pointer the http_parser's owning BaseHttpTransaction object.");
						}

						// TODO - Do we even need this callback? I think not, as the only state information it
						// provides is the determined length of the upcoming chunk, which might be useful for 
						// adjusting payload/body storage containers for when the actual chunk content comes
						// in through the OnBody callback. Leaving the code here anyway, just for the sake
						// of wasting time calling a function that does nothing. ;)

					}
					else
					{
						throw std::runtime_error(u8"In BaseHttpTransaction::OnChunkHeader() - http_parser is nullptr, somehow. \
							This should never be allowed to happen ever because this apparently null object is supposed to be invoking \
							this callback, but if you're reading this, somehow it did. Welcome to the twilight zone. Nobody can wag \
							their finger at me for not wrapping a raw pointer with a null check.");
					}

					return 0;
				}

				int BaseHttpTransaction::OnChunkComplete(http_parser* parser)
				{
					if (parser != nullptr)
					{
						BaseHttpTransaction* trans = static_cast<BaseHttpTransaction*>(parser->data);

						if (trans == nullptr)
						{
							throw std::runtime_error(u8"In BaseHttpTransaction::OnChunkComplete() - http_parser->data is nullptr when it should contain a pointer the http_parser's owning BaseHttpTransaction object.");
						}

						// TODO - Do we even need this callback? Methinks no, see notes in the ::OnChunkHeader
						// implementation.

					}
					else
					{
						throw std::runtime_error(u8"In BaseHttpTransaction::OnChunkComplete() - http_parser is nullptr, somehow. \
							This should never be allowed to happen ever because this apparently null object is supposed to be invoking \
							this callback, but if you're reading this, somehow it did. Welcome to the twilight zone. Nobody can wag \
							their finger at me for not wrapping a raw pointer with a null check.");
					}

					return 0;
				}

				int BaseHttpTransaction::OnHeaderField(http_parser* parser, const char *at, size_t length)
				{
					if (parser != nullptr)
					{
						BaseHttpTransaction* trans = static_cast<BaseHttpTransaction*>(parser->data);

						if (trans == nullptr)
						{
							throw std::runtime_error(u8"In BaseHttpTransaction::OnHeaderField() - http_parser->data is nullptr when it should contain a pointer the http_parser's owning BaseHttpTransaction object.");
						}

						trans->m_lastHeader = std::string(at, length);

						if (length == 0)
						{
							trans->ReportError(u8"In BaseHttpTransaction::OnHeaderField() - Length provided for the parsed header field/name is zero.");
							return -1;
						}
					}
					else
					{
						throw std::runtime_error(u8"In BaseHttpTransaction::OnHeaderField() - http_parser is nullptr, somehow. \
							This should never be allowed to happen ever because this apparently null object is supposed to be invoking \
							this callback, but if you're reading this, somehow it did. Welcome to the twilight zone. Nobody can wag \
							their finger at me for not wrapping a raw pointer with a null check.");
					}

					return 0;
				}

				int BaseHttpTransaction::OnHeaderValue(http_parser* parser, const char *at, size_t length)
				{
					if (parser != nullptr)
					{
						BaseHttpTransaction* trans = static_cast<BaseHttpTransaction*>(parser->data);

						if (trans == nullptr)
						{	
							throw std::runtime_error(u8"In BaseHttpTransaction::OnHeaderValue() - http_parser->data is nullptr when it should contain a pointer the http_parser's owning BaseHttpTransaction object.");
						}

						if (trans->m_lastHeader.length() > 0)
						{							
							std::string headerValue(at, length);
							trans->AddHeader(trans->m_lastHeader, headerValue, false);
						}
						else
						{
							trans->ReportError(std::string(u8"In BaseHttpTransaction::OnHeaderValue() - OnHeaderValue called while BaseHttpTransaction::m_lastHeader was empty."));
							return -1;
						}
					}
					else 
					{
						throw std::runtime_error(u8"In BaseHttpTransaction::OnHeaderValue() - http_parser is nullptr, somehow. \
							This should never be allowed to happen ever because this apparently null object is supposed to be invoking \
							this callback, but if you're reading this, somehow it did. Welcome to the twilight zone. Nobody can wag \
							their finger at me for not wrapping a raw pointer with a null check.");
					}

					return 0;
				}

				int BaseHttpTransaction::OnBody(http_parser* parser, const char *at, size_t length)
				{
					if (parser != nullptr)
					{

						BaseHttpTransaction* trans = static_cast<BaseHttpTransaction*>(parser->data);

						if (trans == nullptr)
						{
							throw std::runtime_error(u8"In BaseHttpTransaction::OnBody() - http_parser->data is nullptr when it should contain a pointer the http_parser's owning BaseHttpTransaction object.");
						}

						trans->m_parsedTransactionData.reserve(trans->m_parsedTransactionData.capacity() + length);
						std::copy(at, at + length, std::back_inserter(trans->m_parsedTransactionData));

						//trans->m_parsedTransactionData.insert(trans->m_parsedTransactionData.end(), at, at + length);						
					}
					else
					{
						throw std::runtime_error(u8"In BaseHttpTransaction::OnBody() - http_parser is nullptr, somehow. \
							This should never be allowed to happen ever because this apparently null object is supposed to be invoking \
							this callback, but if you're reading this, somehow it did. Welcome to the twilight zone. Nobody can wag \
							their finger at me for not wrapping a raw pointer with a null check.");
					}

					return 0;
				}

			} /* namespace http */
		} /* namespace mitm */
	} /* namespace httpengine */
} /* namespace te */