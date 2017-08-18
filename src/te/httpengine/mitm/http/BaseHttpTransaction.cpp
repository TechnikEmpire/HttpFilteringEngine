/*
* Copyright © 2017 Jesse Nicholson
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

#include <sstream>
#include <string>
#include <stdexcept>
#include <utility>
#include <algorithm>
#include <iomanip>
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
					auto nparsed = http_parser_execute(m_httpParser, &m_httpParserSettings, m_buffer.data(), bytesReceived);

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

					return true;
				}

				boost::asio::mutable_buffers_1 BaseHttpTransaction::GetReadBuffer()
				{	
					if (m_buffer.size() < PayloadBufferReadSize)
					{
						m_buffer.resize(PayloadBufferReadSize);
					}

					if (m_headersComplete && !m_consumeAllBeforeSending)
					{
						m_payload.clear();
					}

					return boost::asio::mutable_buffers_1(m_buffer.data(), PayloadBufferReadSize);
				}

				boost::asio::const_buffers_1 BaseHttpTransaction::GetWriteBuffer()
				{
					if (!m_headersSent)
					{
						auto headersVector = HeadersToVector();				
						auto newSize = headersVector.size() + m_payload.size();
						headersVector.reserve(newSize);

						if (m_payload.size() > 0)
						{	
							headersVector.insert(headersVector.end(), m_payload.begin(), m_payload.end());
						}

						m_payload = std::move(headersVector);

						m_headersSent = true;
					}

					return boost::asio::const_buffers_1(m_payload.data(), m_payload.size());
				}

				const std::vector<char>& BaseHttpTransaction::GetPayload() const
				{
					return m_payload;
				}

				void BaseHttpTransaction::SetPayload(std::vector<char>&& payload, const bool includesHeaders)
				{
					m_payload = std::move(payload);
					m_payloadComplete = true;

					if (includesHeaders)
					{
						m_headers.clear();
						m_headersSent = true;
						m_headersComplete = true;
					}
					else
					{
						RemoveHeader(util::http::headers::ContentLength);
						RemoveHeader(util::http::headers::TransferEncoding);
						RemoveHeader(util::http::headers::ContentEncoding);

						auto finalSize = m_payload.size();
						std::string length = std::to_string(finalSize);

						AddHeader(util::http::headers::ContentLength, length);
					}
				}

				void BaseHttpTransaction::SetPayload(const std::vector<char>& payload, const bool includesHeaders)
				{
					m_payload = payload;
					m_payloadComplete = true;

					if (includesHeaders)
					{
						m_headers.clear();
						m_headersSent = true;
						m_headersComplete = true;
					}
					else
					{
						RemoveHeader(util::http::headers::ContentLength);
						RemoveHeader(util::http::headers::TransferEncoding);
						RemoveHeader(util::http::headers::ContentEncoding);

						auto finalSize = m_payload.size();
						std::string length = std::to_string(finalSize);

						AddHeader(util::http::headers::ContentLength, length);
					}
				}

				const bool BaseHttpTransaction::IsPayloadComplete() const
				{
					return m_payloadComplete;
				}

				const int32_t BaseHttpTransaction::GetShouldBlock() const
				{
					return m_shouldBlock;
				}

				void BaseHttpTransaction::SetShouldBlock(const int32_t category)
				{
					m_shouldBlock = category;
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
						break;
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

					m_payload.clear();

					m_payload.assign(fs.begin(), fs.end());

					m_headers.clear();

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
						if (boost::iequals(contentEncoding.first->second, u8"chunked"))
						{
							return true;
						}
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
					if (m_payload.size() == 0)
					{
						ReportWarning(u8"In BaseBridge::CompressDeflate() - There is no payload to compress.");
						return false;
					}

					std::vector<char> compressed;

					try
					{
						boost::iostreams::filtering_ostream os;

						os.push(boost::iostreams::gzip_compressor());
						os.push(boost::iostreams::back_inserter(compressed));

						boost::iostreams::write(os, m_payload.data(), m_payload.size());
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
					if (m_payload.size() == 0)
					{
						ReportWarning(u8"In BaseBridge::CompressDeflate() - There is no payload to compress.");
						return false;
					}

					std::vector<char> compressed;

					try
					{
						boost::iostreams::filtering_ostream os;

						os.push(boost::iostreams::zlib_compressor());
						os.push(boost::iostreams::back_inserter(compressed));

						boost::iostreams::write(os, m_payload.data(), m_payload.size());
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
					if (m_payload.size() == 0)
					{
						ReportError(u8"In BaseBridge::DecompressGzip() - There is no payload to decompress.");
						return false;
					}

					std::vector<char> decompressed;
					decompressed.reserve(m_payload.size());

					try
					{
						// For some reason, all the example code that boost gives, and all the examples
						// you'll find of "this works" in terms of using boost::asio::gzip streams do
						// not function correctly here. This code does.
						boost::iostreams::back_insert_device< std::vector<char> > decompressorSnk(decompressed);
						boost::iostreams::gzip_decompressor decomp(boost::iostreams::zlib::default_window_bits);
						decomp.write(decompressorSnk, m_payload.data(), m_payload.size());
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
					if (m_payload.size() == 0)
					{
						ReportError(u8"In BaseBridge::DecompressDeflate() - There is no payload to decompress.");
						return false;
					}

					std::vector<char> decompressed;
					decompressed.reserve(m_payload.size());

					try
					{
						/*
						boost::iostreams::filtering_ostream os;

						os.push(boost::iostreams::zlib_decompressor());
						os.push(std::back_inserter(decompressed));

						boost::iostreams::write(os, m_payload.data(), m_payload.size());
						*/
						
						// For some reason, all the example code that boost gives, and all the examples
						// you'll find of "this works" in terms of using boost::asio::gzip streams do
						// not function correctly here. This code does.
						boost::iostreams::back_insert_device< std::vector<char> > decompressorSnk(decompressed);
						boost::iostreams::zlib_decompressor decomp(boost::iostreams::zlib::default_window_bits);
						decomp.write(decompressorSnk, m_payload.data(), m_payload.size());
						
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
			
				const bool BaseHttpTransaction::ConvertPayloadFromChunkedToFixedLength()
				{
					std::vector<char> parsedBody;
					parsedBody.reserve(m_payload.size());

					http_parser_settings parserSettings;

					auto onDataGeneric = [](http_parser* parser, const char *at, size_t length)->int
					{
						// This is made to accept but ignore data callbacks we don't care about.
						return 0;
					};

					auto onNotificationGeneric = [](http_parser* parser)->int
					{
						// This is made to accept but ignore notification callbacks we don't care about.
						return 0;
					};

					auto onBody = [](http_parser* parser, const char *at, size_t length)->int
					{
						if (parser->data == nullptr)
						{
							return -1;
						}

						auto bodyContainer = static_cast<std::vector<char>*>(parser->data);
						std::copy(at, at + length, std::back_inserter(*bodyContainer));
						return 0;
					};

					parserSettings.on_body = onBody;
					parserSettings.on_chunk_complete = onNotificationGeneric;
					parserSettings.on_chunk_header = onNotificationGeneric;
					parserSettings.on_headers_complete = onNotificationGeneric;
					parserSettings.on_header_field = onDataGeneric;
					parserSettings.on_header_value = onDataGeneric;
					parserSettings.on_message_begin = onNotificationGeneric;
					parserSettings.on_message_complete = onNotificationGeneric;
					parserSettings.on_status = onDataGeneric;
					parserSettings.on_url = onDataGeneric;					

					http_parser* parser;
					parser = static_cast<http_parser*>(malloc(sizeof(http_parser)));

					if (!parser)
					{
						std::string error(u8"In BaseHttpTransaction::ConvertPayloadFromChunkedToFixedLength() - Failed to allocate memory for http-parser.");
						ReportError(error);
						return false;
					}

					http_parser_init(parser, HTTP_BOTH);

					parser->data = &parsedBody;

					std::vector<char> finalVec = HeadersToVector();
					auto newSize = finalVec.size() + m_payload.size();
					finalVec.reserve(newSize);

					if (m_payload.size() > 0)
					{
						finalVec.insert(finalVec.end(), m_payload.begin(), m_payload.end());
					}

					auto nparsed = http_parser_execute(parser, &parserSettings, finalVec.data(), finalVec.size());

					if (parser->http_errno != 0)
					{
						auto errorMessage = std::string(u8"In BaseHttpTransaction::ConvertPayloadFromChunkedToFixedLength() - Got http_parser error: ");
						errorMessage.append(http_errno_description(HTTP_PARSER_ERRNO(parser)));
						ReportError(errorMessage);						
						free(parser);

						auto body = std::string(finalVec.data());
						ReportError(body);

						return false;
					}

					if (parsedBody.size() <= 0)
					{
						std::string errorMessage(u8"In BaseHttpTransaction::ConvertPayloadFromChunkedToFixedLength() - Finalized payload is empty.");
						ReportWarning(errorMessage);
						free(parser);
						return false;
					}

					// If the payload is not compressed, we can simply set the payload and it
					// will adjust our headers properly to make it a fixed length transaction.
					if (!IsPayloadCompressed())
					{	
						SetPayload(std::move(parsedBody));						
					}
					else
					{
						m_payload = std::move(parsedBody);

						// If the payload is compressed, calling the decompress function
						// will handle mutating our headers correctly to make it a fixed
						// length transaction.
						if (!DecompressPayload())
						{
							std::string errorMessage(u8"In BaseHttpTransaction::ConvertPayloadFromChunkedToFixedLength() - Failed to decompress payload.");
							ReportError(errorMessage);							
							free(parser);
							return false;
						}
					}

					free(parser);
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
						trans->m_lastHeaderValueFresh = false;
						trans->m_lastHeaderFieldFresh = false;
						
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

						// When the payload is complete, and we want to consume it all, we need to convert it
						// from chunked encoding to a fixed length payload.
						if (trans->GetConsumeAllBeforeSending())
						{	
							trans->ConvertPayloadFromChunkedToFixedLength();
							/*
							if (trans->IsPayloadChunked())
							{
								trans->ConvertPayloadFromChunkedToFixedLength();
							}
							else if (trans->IsPayloadCompressed())
							{
								trans->DecompressPayload();
							}
							*/
						}
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

						std::stringstream chunkHeaderSs;
						chunkHeaderSs << std::hex << parser->content_length;
						chunkHeaderSs << u8"\r\n";
						std::string chunkHeader(chunkHeaderSs.str());
						trans->m_payload.insert(trans->m_payload.end(), chunkHeader.begin(), chunkHeader.end());
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

						trans->m_payload.push_back('\r');
						trans->m_payload.push_back('\n');
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
						
						if (trans->m_lastHeaderFieldFresh)
						{
							trans->m_lastHeader = std::string(at, length);
							trans->m_lastHeaderFieldFresh = false;
						}
						else
						{
							trans->m_lastHeader.append(std::string(at, length));
						}
						
						trans->m_lastHeaderValueFresh = true;

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

						trans->m_lastHeaderFieldFresh = true;

						if (trans->m_lastHeader.length() > 0)
						{	
							if (trans->m_lastHeaderValueFresh)
							{
								std::string headerValue(at, length);
								trans->AddHeader(trans->m_lastHeader, headerValue, false);			
								trans->m_lastHeaderValueFresh = false;
							}
							else
							{
								// Since we're not guaranteed to be given all of our header data
								// in one shot, we must assume that this data is meant to be appended
								// to the last entered header.
								auto range = trans->m_headers.equal_range(trans->m_lastHeader); 
								
								if (range.first != range.second)
								{	
									auto appender = std::prev(range.second);
									
									// Ordering is supposed to be guaranteed. This must be it.
									appender->second.append(std::string(at, length));
								}
							}
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

						trans->m_payload.reserve(trans->m_payload.capacity() + length);
						std::copy(at, at + length, std::back_inserter(trans->m_payload));
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