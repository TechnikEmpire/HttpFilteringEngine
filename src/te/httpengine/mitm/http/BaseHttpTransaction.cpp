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

					if (!m_headersComplete)
					{
						const char* data = boost::asio::buffer_cast<const char*>(m_headerBuffer.data());

						// The parser must ALWAYS be called first. The OnMessageBegin callback will reset the state
						// of this object, clearing everything including payload data. If the parser is called second,
						// this transaction will be irreparably broken.
						auto nparsed = http_parser_execute(m_httpParser, &m_httpParserSettings, data, m_headerBuffer.size());

						if (nparsed != m_headerBuffer.size())
						{
							if (m_httpParser->http_errno != 0)
							{
								std::string errMsg(u8"In BaseHttpTransaction::Parse(const size_t&) - Failed to parse headers. Got http_parser error number: ");
								errMsg.append(std::to_string(m_httpParser->http_errno));
								ReportError(errMsg);
								return false;
							}
							else
							{
								ReportWarning(u8"In BaseHttpTransaction::Parse(const size_t&) - While parsing headers, not all bytes were parsed, but http_parser reports no error. This may be a sign that the parsing calculation is incorrect.");
							}							
						}

						if (bytesReceived < m_headerBuffer.size())
						{
							// Body/payload data has come through into our header buffer. This data must be
							// copied out to the m_transactionPayload vector.
							std::istreambuf_iterator<char> extraDataStart(&m_headerBuffer);

							// Store exactly how much payload/body data is being copied out to the payload vector.
							m_unwrittenPayloadSize = (m_headerBuffer.size() - bytesReceived);

							size_t offset = bytesReceived;

							while (offset > 0)
							{
								extraDataStart++;
								offset--;
							}

							// Copy the payload data to the request transaction payload vector
							std::copy(extraDataStart, std::istreambuf_iterator<char>(), std::back_inserter(m_transactionData));
						}

						success = true;
					}
					else 
					{
						auto nparsed = http_parser_execute(m_httpParser, &m_httpParserSettings, m_transactionData.data() + m_unwrittenPayloadSize, bytesReceived);

						m_unwrittenPayloadSize += bytesReceived;

						if (nparsed != bytesReceived)
						{
							if (m_httpParser->http_errno != 0)
							{
								std::string errMsg(u8"In BaseHttpTransaction::Parse(const size_t&) - Failed to parse payload. Got http_parser error number: ");
								errMsg.append(std::to_string(m_httpParser->http_errno));
								ReportError(errMsg);
								return false;
							}
							else
							{
								ReportWarning(u8"In BaseHttpTransaction::Parse(const size_t&) - While parsing payload, not all bytes were parsed, but http_parser reports no error. This may be a sign that the parsing calculation is incorrect.");
							}							
						}
					}

					// If the body is complete, then we need to provide some things which are guaranteed, such as
					// automatic decompression when ::ConsumeAllBeforeSending() is true, and automatic conversion
					// of chunked transfers to fixed-length/precalculated (content-length header defined) transfers.
					if (m_payloadComplete && m_consumeAllBeforeSending)
					{
						bool finalizationFailed = false;

						const auto transferEncoding = GetHeader(util::http::headers::TransferEncoding);
						
						if (transferEncoding.first != transferEncoding.second)
						{
							RemoveHeader(util::http::headers::TransferEncoding);
							
							if (!ConvertPayloadFromChunkedToFixedLength())
							{
								// No need to generate messages here, the method itself will do so.
								finalizationFailed = true;
							}
						}

						const auto contentEncoding = GetHeader(util::http::headers::ContentEncoding);

						if (contentEncoding.first != contentEncoding.second)
						{
							if (boost::iequals(contentEncoding.first->second, u8"gzip"))
							{
								if (!DecompressGzip())
								{
									// We will report an error, but will not abort further operations, since even if this fails,
									// the transaction can theoretically be simply passed on to the client. 
									finalizationFailed = true;
									ReportError("In BaseHttpTransaction::Parse(const size_t&) - Failed to decompress Gzip encoded payload!");
								}
								else
								{
									RemoveHeader(util::http::headers::ContentEncoding);
								}
							}
							else if(boost::iequals(contentEncoding.first->second, u8"deflate"))
							{
								if (!DecompressDeflate())
								{
									// We will report an error, but will not abort further operations, since even if this fails,
									// the transaction can theoretically be simply passed on to the client. 
									finalizationFailed = true;
									ReportError("In BaseHttpTransaction::Parse(const size_t&) - Failed to decompress Deflate encoded payload!");
								}
								else
								{
									RemoveHeader(util::http::headers::ContentEncoding);
								}
							}
							else
							{
								finalizationFailed = true;
								ReportError("In BaseHttpTransaction::Parse(const size_t&) - Unknown Content-Encoding, cannot decompress: " + contentEncoding.first->second);
							}							
						}

						success = !finalizationFailed;

						// Ensure that the terminating CRLF's are present and that they are not factored
						// into Content-Length calculation.

						if (
							m_transactionData[m_transactionData.size() - 4] == '\r' &&
							m_transactionData[m_transactionData.size() - 3] == '\n' &&
							m_transactionData[m_transactionData.size() - 2] == '\r' &&
							m_transactionData[m_transactionData.size() - 1] == '\n'
							)
						{
							AddHeader(util::http::headers::ContentLength, std::to_string(m_transactionData.size() - 4), true);
						}
						else {

							AddHeader(util::http::headers::ContentLength, std::to_string(m_transactionData.size()), true);
							
							m_transactionData.push_back('\r');
							m_transactionData.push_back('\n');
							m_transactionData.push_back('\r');
							m_transactionData.push_back('\n');
						}

						// Reset the size, in case pushing terminating CRLF's adjusted it. Must be done, otherwise
						// we'll ruin keep-alive.
						m_unwrittenPayloadSize = m_transactionData.size();
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
					// From the docs: http://www.boost.org/doc/libs/1_59_0/doc/html/boost_asio/reference/buffer.html
					// "Note that a vector is never automatically resized when creating or using a buffer. The buffer 
					// size is determined using the vector's size() member function, and not its capacity."
					//
					// So, we need to keep resizing the vector buffer in order to make more room for new incoming data,
					// which presents a problem. Since the ::size() method is used for telling how much room there is
					// to populate when a vector is supplied as a buffer, and size() is what we'd normally count on
					// to tell us how much data is already written in, we're screwed. I quit. Just kidding, but this
					// means that we need to track the size of previously read data in a member variable.
					//
					// Then, we need to keep doing some maths and resizing (not reserving) the vector every time we do
					// new reads, but only in the case where ::ConsumeAllBeforeSending() is true.

					// First thing we want to do is resize the buffer, if it needs to be resized. Warning, incoming
					// hardcoded values. In my testing, 131072 gives a nice balance for keeping allocations to a 
					// minimum, since most content that we're concerned about keeping should come in well under that.
					if (m_transactionData.size() < PayloadBufferReadSize)
					{
						m_transactionData.resize(PayloadBufferReadSize);
					}

					if (m_consumeAllBeforeSending == false)
					{
						// This is easy, leave the buffer at its current size and just return it. Any existing data
						// will be overwritten, and in the ::Parse(...) method, m_unwrittenPayloadSize will be
						// adjusted to reflect the length of the accurate data.
						return boost::asio::mutable_buffers_1(m_transactionData.data(), m_transactionData.size());
					}

					if (m_consumeAllBeforeSending && m_unwrittenPayloadSize > 0)
					{
						if (m_transactionData.size() < MaxPayloadResize)
						{
							// So, if the payload container already contains data, and we want to read more, and the 
							// difference between the size of the existing valid data and the size of the container
							// is less than our hard-coded buffer size of 131072, resize the container so it has
							// 131072 bytes available for populating.
							// This way, we should always have a buffer length of 131072.
							if ((m_transactionData.size() - m_unwrittenPayloadSize) < PayloadBufferReadSize)
							{
								m_transactionData.resize(m_transactionData.size() + (PayloadBufferReadSize - (m_transactionData.size() - m_unwrittenPayloadSize)));
							}
						}
						else
						{
							throw std::runtime_error(u8"In BaseHttpTransaction::GetPayloadReadBuffer() - Maximum buffer size reached.");
						}						
					}

					return boost::asio::mutable_buffers_1(m_transactionData.data() + m_unwrittenPayloadSize, PayloadBufferReadSize);
				}

				boost::asio::const_buffers_1 BaseHttpTransaction::GetWriteBuffer()
				{
					if (!m_headersSent)
					{
						auto headersVector = HeadersToVector();				

						headersVector.reserve(headersVector.capacity() + m_transactionData.size());

						headersVector.insert(headersVector.end(), std::make_move_iterator(m_transactionData.begin()), std::make_move_iterator(m_transactionData.begin() + m_unwrittenPayloadSize));

						m_transactionData = std::move(headersVector);

						m_unwrittenPayloadSize = m_transactionData.size();

						m_headersSent = true;
					}

					size_t bytesToWrite = m_unwrittenPayloadSize;					

					// When you've called for a write, you've called for a write. Everything is
					// turned into a finalized state, the state information that was used for
					// keeping track of things like partial reads etc is all gone.
					m_unwrittenPayloadSize = 0;

					return boost::asio::const_buffers_1(m_transactionData.data(), bytesToWrite);
				}

				const std::vector<char>& BaseHttpTransaction::GetPayload() const
				{
					return m_transactionData;
				}

				void BaseHttpTransaction::SetPayload(std::vector<char>&& payload)
				{
					// XXX TODO - Cleanup this code duplication.

					m_transactionData = std::move(payload);					
					m_payloadComplete = true;
										
					RemoveHeader(util::http::headers::ContentLength);
					RemoveHeader(util::http::headers::TransferEncoding);
					RemoveHeader(util::http::headers::ContentEncoding);					

					if (
						m_transactionData.size() >= 4 &&
						m_transactionData[m_transactionData.size() - 4] == '\r' &&
						m_transactionData[m_transactionData.size() - 3] == '\n' &&
						m_transactionData[m_transactionData.size() - 2] == '\r' &&
						m_transactionData[m_transactionData.size() - 1] == '\n'
						)
					{
						auto sizeString = std::to_string(payload.size() - 4);
						AddHeader(util::http::headers::ContentLength, sizeString);
					}
					else 
					{

						auto sizeString = std::to_string(payload.size());
						AddHeader(util::http::headers::ContentLength, sizeString);

						m_transactionData.push_back('\r');
						m_transactionData.push_back('\n');
						m_transactionData.push_back('\r');
						m_transactionData.push_back('\n');
					}

					// Reset the size, in case pushing terminating CRLF's adjusted it. Must be done, otherwise
					// we'll ruin keep-alive.
					m_unwrittenPayloadSize = m_transactionData.size();
				}

				void BaseHttpTransaction::SetPayload(const std::vector<char>& payload)
				{
					// XXX TODO - Cleanup this code duplication.

					m_transactionData = payload;
					
					m_payloadComplete = true;

					RemoveHeader(util::http::headers::ContentLength);
					RemoveHeader(util::http::headers::TransferEncoding);
					RemoveHeader(util::http::headers::ContentEncoding);

					if (
						m_transactionData.size() >= 4 &&
						m_transactionData[m_transactionData.size() - 4] == '\r' &&
						m_transactionData[m_transactionData.size() - 3] == '\n' &&
						m_transactionData[m_transactionData.size() - 2] == '\r' &&
						m_transactionData[m_transactionData.size() - 1] == '\n'
						)
					{
						auto sizeString = std::to_string(payload.size() - 4);
						AddHeader(util::http::headers::ContentLength, sizeString);
					}
					else
					{

						auto sizeString = std::to_string(payload.size());
						AddHeader(util::http::headers::ContentLength, sizeString);

						m_transactionData.push_back('\r');
						m_transactionData.push_back('\n');
						m_transactionData.push_back('\r');
						m_transactionData.push_back('\n');
					}

					// Reset the size, in case pushing terminating CRLF's adjusted it. Must be done, otherwise
					// we'll ruin keep-alive.
					m_unwrittenPayloadSize = m_transactionData.size();
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
					m_payloadComplete = true;
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

					m_transactionData.clear();

					m_transactionData.assign(fs.begin(), fs.end());

					m_headersSent = true;
					m_headersComplete = true;
				}

				const bool BaseHttpTransaction::GetConsumeAllBeforeSending() const
				{
					return m_consumeAllBeforeSending;
				}

				void BaseHttpTransaction::SetConsumeAllBeforeSending(const bool value)
				{
					m_consumeAllBeforeSending = value;
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
					}else if (DoesContentTypeContain(ContentTypeHtml))
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

					if (contentTypeHeader.first != contentTypeHeader.second)
					{
						while (contentTypeHeader.first != contentTypeHeader.second)
						{
							if (boost::ifind_first(contentTypeHeader.first->second, type))
							{
								return true;
							}

							contentTypeHeader.first++;
						}
					}

					return false;
				}

				const bool BaseHttpTransaction::CompressGzip()
				{
					if (m_transactionData.size() == 0)
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

						boost::iostreams::write(os, m_transactionData.data(), m_unwrittenPayloadSize);
					}
					catch (std::exception &e)
					{
						std::string errMessage("In BaseBridge::CompressGzip() - Exception while compressing: ");
						errMessage.append(e.what());
						ReportError(errMessage);
						return false;
					}

					if (m_transactionData.size() > compressed.size())
					{
						m_transactionData = std::move(compressed);
						std::string gzip(u8"gzip");
						AddHeader(util::http::headers::ContentEncoding, gzip);
						return true;
					}
					else {
						return false;
					}
				}

				const bool BaseHttpTransaction::CompressDeflate()
				{
					if (m_transactionData.size() == 0)
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

						boost::iostreams::write(os, m_transactionData.data(), m_unwrittenPayloadSize);
					}
					catch (std::exception &e)
					{
						std::string errMessage("In BaseBridge::CompressDeflate() - Exception while compressing: ");
						errMessage.append(e.what());
						ReportError(errMessage);
						return false;
					}

					if (m_transactionData.size() > compressed.size())
					{
						m_transactionData = std::move(compressed);
						std::string deflate(u8"deflate");
						AddHeader(util::http::headers::ContentEncoding, deflate);
						return true;
					}
					else {
						return false;
					}
				}

				const bool BaseHttpTransaction::DecompressGzip()
				{
					if (m_transactionData.size() == 0)
					{
						ReportError(u8"In BaseBridge::DecompressGzip() - There is no payload to decompress.");
						return false;
					}

					// Must trim off unusued allocated space.
					if (m_transactionData.size() > m_unwrittenPayloadSize)
					{
						m_transactionData.resize(m_unwrittenPayloadSize);
					}

					// If the terminating CRLF's on the payload are left, they'll screw with
					// decompression. They need to be trimmed first.
					if (
						m_transactionData.at(m_transactionData.size() - 4) == '\r' &&
						m_transactionData.at(m_transactionData.size() - 3) == '\n' &&
						m_transactionData.at(m_transactionData.size() - 2) == '\r' &&
						m_transactionData.at(m_transactionData.size() - 1) == '\n'
						)
					{
						m_transactionData.resize(m_transactionData.size() - 4);
					}

					std::vector<char> decompressed;

					try
					{
						boost::iostreams::filtering_streambuf<boost::iostreams::input> in;

						in.push(boost::iostreams::gzip_decompressor());
						in.push(boost::iostreams::array_source(m_transactionData.data(), m_unwrittenPayloadSize));

						boost::iostreams::copy(in, std::back_insert_iterator<std::vector<char>>(decompressed));

					}
					catch (std::exception& e)
					{
						std::string errMessage(u8"In BaseBridge::DecompressGzip() - Exception while decompressing: ");
						errMessage.append(e.what());
						ReportError(errMessage);
						return false;
					}

					if (decompressed.size() > 0)
					{
						m_transactionData = std::move(decompressed);
						m_unwrittenPayloadSize = m_transactionData.size();
						return true;
					}
					else {
						return false;
					}
				}

				const bool BaseHttpTransaction::DecompressDeflate()
				{
					if (m_transactionData.size() == 0)
					{
						ReportError(u8"In BaseBridge::DecompressDeflate() - There is no payload to decompress.");
						return false;
					}

					// Must trim off unusued allocated space.
					if (m_transactionData.size() > m_unwrittenPayloadSize)
					{
						m_transactionData.resize(m_unwrittenPayloadSize);
					}

					// If the terminating CRLF's on the payload are left, they'll screw with
					// decompression. They need to be trimmed first.
					if (
						m_transactionData.at(m_transactionData.size() - 4) == '\r' &&
						m_transactionData.at(m_transactionData.size() - 3) == '\n' &&
						m_transactionData.at(m_transactionData.size() - 2) == '\r' &&
						m_transactionData.at(m_transactionData.size() - 1) == '\n'
						)
					{
						m_transactionData.resize(m_transactionData.size() - 4);
					}

					std::vector<char> decompressed;

					try
					{
						boost::iostreams::filtering_streambuf<boost::iostreams::input> in;

						in.push(boost::iostreams::zlib_decompressor());
						in.push(boost::iostreams::array_source(m_transactionData.data(), m_unwrittenPayloadSize));

						boost::iostreams::copy(in, std::back_insert_iterator<std::vector<char>>(decompressed));

					}
					catch (std::exception& e)
					{
						std::string errMessage(u8"In BaseBridge::DecompressDeflate() - Exception while decompressing: ");
						errMessage.append(e.what());
						ReportError(errMessage);
						return false;
					}

					if (decompressed.size() > 0)
					{
						m_transactionData = std::move(decompressed);
						m_unwrittenPayloadSize = m_transactionData.size();
						return true;
					}
					else {
						return false;
					}
				}

				const bool BaseHttpTransaction::ConvertPayloadFromChunkedToFixedLength()
				{
					const boost::string_ref crlf = u8"\r\n";

					// First we need to cut down the payload buffer to the exact size of how many bytes
					// we've received.
					if (m_transactionData.size() > m_unwrittenPayloadSize)
					{
						m_transactionData.resize(m_unwrittenPayloadSize);
					}					

					boost::string_ref payloadStrRef(m_transactionData.data(), m_transactionData.size());

					// All chunked content will be moved into this container, and m_transactionData
					// will be reassigned to it on a successful conversion.
					std::vector<char> result;
					result.reserve(m_transactionData.size());

					// Get the first position of the end of the first chunk header
					auto pos = payloadStrRef.find(crlf);

					std::stringstream ss;

					size_t chunkLength = 0;

					bool noError = false;

					size_t globalPos = 0;

					while (pos != boost::string_ref::npos)
					{
						chunkLength = 0;

						// Completely reset the stream
						ss.str(std::string());
						ss.clear();

						boost::string_ref chunkLenStr = payloadStrRef.substr(0, pos);

						auto chunkLengthTrailerPos = chunkLenStr.find(';');

						if (chunkLengthTrailerPos != boost::string_ref::npos)
						{
							chunkLenStr = chunkLenStr.substr(0, chunkLengthTrailerPos);
						}

						ss << std::hex << chunkLenStr;

						if (ss.fail())
						{
							ReportError(u8"In BaseHttpTransaction::ConvertPayloadFromChunkedToFixedLength() - Chunk length conversion to integer value failed.");
							break;
						}

						ss >> chunkLength;

						if (chunkLength == 0)
						{
							// All data has been read if we've reached the terminating chunk header
							// which defines a length of zero.
							noError = true;
							break;
						}

						// Advance beyond the chunk length terminating crlf.
						pos += crlf.size();

						if ((pos + chunkLength) > payloadStrRef.size())
						{
							ReportError(u8"In BaseHttpTransaction::ConvertPayloadFromChunkedToFixedLength() - New chunk length specified is greater than the total payload container size.");
							break;
						}

						globalPos += pos;

						// We know have a chunk, its start position and its end position. Move it.
						// XXX TODO - Change this to a straight up copy, moving char is slower.
						result.insert(result.end(), (m_transactionData.begin() + globalPos), (m_transactionData.begin() + (globalPos + chunkLength)));

						// Advance pos beyond clrf at the start of the chunk, then beyond the chunk length, then again beyond the
						// terminating clrf before we search again.
						pos += (chunkLength + crlf.size());
						globalPos += (chunkLength + crlf.size());
						
						if (pos > payloadStrRef.length())
						{
							ReportError(u8"In BaseHttpTransaction::ConvertPayloadFromChunkedToFixedLength() - Next chunk length specified is greater than the total payload container size.");
							break;
						}						

						payloadStrRef = payloadStrRef.substr(pos);

						pos = payloadStrRef.find(crlf);

						if (pos == boost::string_ref::npos)
						{
							ReportError(u8"In BaseHttpTransaction::ConvertPayloadFromChunkedToFixedLength() - Final chunk not yet encountered, but failed to locate the next chunk header.");
							break;
						}
					}

					if (noError)
					{
						m_transactionData = std::move(result);
						m_unwrittenPayloadSize = m_transactionData.size();
					}
					else
					{
						ReportError(u8"In BaseHttpTransaction::ConvertPayloadFromChunkedToFixedLength() - Failed to convert chunked content to fixed-length transfer.");
					}

					return noError;
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
						trans->m_unwrittenPayloadSize = 0;
						trans->m_headersSent = false;
						trans->m_headersComplete = false;
						trans->m_transactionData.clear();
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

							trans->m_lastHeader.clear();
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
						/*

						This method has been disabled due to a design change decision. Formerly, this object
						was not going to own the buffers used for reading the raw data it is intended to parse.
						However, having considered design issues that are much uglier than this object owning
						read buffers, I've decided to make this object own the read buffers. As such, this
						method is no longer required for copying out body data, as the body data will already
						exist inside this object however it comes in over the wire. From there, the body
						may or may not be converted from chunked to a fixed-length body, etc, depending
						on configuration options, at which time the same raw read buffers will be mutated
						accordingly. See notes on the ::Parse(const size_t&) method for more information.

						BaseHttpTransaction* trans = static_cast<BaseHttpTransaction*>(parser->data);

						if (trans == nullptr)
						{
							throw std::runtime_error(u8"In BaseHttpTransaction::OnBody() - http_parser->data is nullptr when it should contain a pointer the http_parser's owning BaseHttpTransaction object.");
						}

						trans->m_transactionData.insert(trans->m_transactionData.end(), at, at + length);
						*/
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