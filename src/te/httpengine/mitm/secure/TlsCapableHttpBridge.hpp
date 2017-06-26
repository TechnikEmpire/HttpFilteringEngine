/*
* Copyright © 2017 Jesse Nicholson
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

#pragma once

#include <boost/predef/architecture.h>
#include <boost/predef/os.h>
#include <boost/predef/compiler.h>
#include <boost/algorithm/string.hpp>
#include "../../network/SocketTypes.hpp"
#include "BaseInMemoryCertificateStore.hpp"
#include "../http/HttpRequest.hpp"
#include "../http/HttpResponse.hpp"
#include "../../util/cb/EventReporter.hpp"
#include "../../../util/http/KnownHttpHeaders.hpp"
#include <memory>
#include <atomic>
#include <type_traits>

#if BOOST_OS_WINDOWS

	#if BOOST_ARCH_X86_32
		#ifdef _MSC_VER
			#define cpu_relax() _mm_pause()
		#else
			#define cpu_relax() asm volatile("pause" ::: "memory")
		#endif
	#elif BOOST_ARCH_X86_64
		#ifdef _MSC_VER
			#define cpu_relax() _mm_pause()
		#else
			#define cpu_relax() asm volatile("pause" ::: "memory")
		#endif
	#else
		#if BOOST_COMP_MSVC_BUILD || BOOST_COMP_MSVC
			#pragma message ("Relax instruction for ::Kill() member spinlock for ARCH not implemented.")
		#elif BOOST_COMP_GNUC
			#warning "Relax instruction for ::Kill() member spinlock for ARCH not implemented."
		#elif BOOST_COMP_CLANG
			#warning "Relax instruction for ::Kill() member spinlock for ARCH not implemented."
		#endif
	#endif
#else
	// XXX TODO - Ensure we've got cpu_relax for other platforms.
#endif	

/*
*					TLS Bridge Control Flow
*
*    +------------------------------+
*    |                              |
*    |    Client socket connects.   +-------------+
*    |                              |             |
*    +------------------------------+             |
*                                                 |
*    +---------------------------+     +----------v-------------+
*    |                           <--+  | Read host information  |
* +--+ Connect upstream to host. |  |  | from TLS client hello. +--^
* |  |                           |  |  +------------------------+  |
* |  +---------------------------+  |  +------------------------+  |
* |                                 |  | Resolve the extracted  |  |
* |  +---------------------------+  +--+ host address.          <--+
* +-->                           |     +------------------------+
*    | Perform handshake with    |
*    | the upstream server. Get  |     +------------------------+
*    | the server's certificate. +---->+ Ask cert store to spoof+--+
*    |                           |     | or get existing cert.  |  |
*    +---------------------------+     +------------------------+  |
*                                                                  |
*    +---------------------------+     +------------------------+  |
*    | Read downstream client    <-----+ Perform downstream     +<-+
*    | request headers. Adjust   |     | client handshake.      |
*    | socket options such as    |     +------------------------+
*    | keep-alive etc to match   |
*    | the client settings.      |     +---------------------------+
*    |                           +-----> Attempt to filter the     |
*    +---------------------------+     | request immediately based |
*                                      | solely on the host and    |
*   +----------------------------+     | request URI information.  |
*   | Read server response       |     | Write client headers to   |
*   | headers. Attempt to filter <-----+ upstream server.          |
*   | the request again by using |     +---------------------------+
*   | content-type info.         |
*   | If response body, and      |     +---------------------------+
*   | inspection desired, read   +-----> If body inspected, filter |
*   | from server again until    |     | when read complete, write |
*   | the entire chunked response|     | to client.                |
*   | has been read, or total    |     +-------------+-------------+
*   | bytes read  equals content |                   |
*   | length header value.       |     +-------------v-------------+
*   |                            |     | When response is fully    |
*   | If inspection is not wanted|     | written to client, if     |
*   | then write to client, then |     | keep-alive specified,     |
*   | initate read from server,  |     | re-initiate process at    |
*   | write to client volley     +---->+ reading client headers    |
*   | until transfer complete.   |     | stage.                    |
*   +----------------------------+     +---------------------------+

	Note that the above flow is basically identical for insecure clients
	aka plain TCP HTTP clients. Rather than a peek read, handshake, spoof,
	handshake, we jump right to the client's headers.
*/

namespace te
{
	namespace httpengine
	{
		namespace mitm
		{
			namespace secure
			{								

				/// <summary>
				/// The TlsCapableHttpBridge serves as the friendly MITM for HTTP/HTTPS transactions.
				/// The purpose of this class is to act transparently on behalf of the downstream
				/// client, fulfilling requests to the original remote peer the connected client
				/// sought. By transparently fulfilling these requests, this class can employ all of
				/// the filtering mechanisms provided to it to filter connections and content on
				/// behalf of the downstream client, before the content reaches the client.
				/// 
				/// It is also the burden of this class, when BridgeSocketType is
				/// network::TlsSocket, to seek and verify SSL certificates before requesting that
				/// the supplied in memory certificate store generate a server context that can be
				/// used to transparently serve the secured client. That is, if a secure client
				/// connects requesting a host for which there is currently no spoofed certificate
				/// and corresponding SSL context, this class has the burden of connecting to the
				/// requested host, fetching the real certificate, verifying it, then and only then
				/// (verified), requesting the supplied in memory store to spoof and generate a
				/// context that this bridge can use.
				/// 
				/// Since this class enforces TLS when serving a secure client, and parsing SNI is
				/// required in order to know which host to seek upstream so that its certificate
				/// might be verified and spoofed, so we have generated contexts to serve secure
				/// clients, this class needs to be able to parse the SNI extension of TLS client
				/// hello messages.
				/// 
				/// A soon as a secure client connects, a peek read is done against the client
				/// socket to attempt to get, at the very least, the SNI hostname portion of the
				/// hello from the client. There is an "official" implementation of this
				/// functionality in openSSL, but it requires static callbacks with user data
				/// supplied via void pointers, and these callbacks can only be bound to a single
				/// context (in our case, the global default server context). As such it's a
				/// prohibitively difficult task to use this functionality while maintaining our
				/// per-client/per-connection class context. So, rather than using the provided API,
				/// we parse it manually according the spec.
				/// 
				/// Presently this class is tighly bound to the intended functionality of the
				/// library: to provide filtering of requests and content based on Adblock Plus
				/// formatted filters and CSS selectors.
				/// </summary>
				template<class BridgeSocketType>				
				class TlsCapableHttpBridge : public std::enable_shared_from_this< TlsCapableHttpBridge<BridgeSocketType> >, public util::cb::EventReporter
				{
					
				/// <summary>
				/// Enforce use of this class to the only two types of sockets it is intended to be
				/// used with.
				/// </summary>
				static_assert((std::is_same<BridgeSocketType, network::TcpSocket> ::value || std::is_same<BridgeSocketType, network::TlsSocket>::value), "TlsCapableHttpBridge can only accept boost::asio::ip::tcp::socket or boost::asio::ssl::stream<boost::asio::ip::tcp::socket> as valid template parameters.");

				public:
					
					/// <summary>
					/// Constructs a new TlsCapableHttpBridge instance. A single constructor
					/// declaration is used for both types of supported bridges, plain TCP and SSL
					/// Stream based. Template specialization is used to define varying forms of the
					/// constructors, simply to allow for correct member initialization. In the case
					/// of unsecure or plain TCP socket based bridge, all SSL/TLS related parameters
					/// are ignored. In the event of a secure or SSL Stream based bridge, the
					/// parameters are required.
					/// </summary>
					/// <param name="service">
					/// A valid pointer to the boost::asio::io_service that will drive the member
					/// sockets, resolver, strands and timer.
					/// </param>
					/// <param name="certStore">
					/// A pointer to the in-memory certificate store responsible for spoofing
					/// certificates and corresponding server SSL contexts on demand. Not required
					/// or used in the event that BridgeSocketType is network::TcpSocket, required
					/// to be valid when BridgeSocketType is network::TlsSocket. Stores implement
					/// various locking mechanism to ensure thread safety and are designed for a
					/// single instance to be shared.
					/// </param>
					/// <param name="defaultServerContext">
					/// A pointer to the default server context. Not required or used when
					/// BridgeSocketType is network::TcpSocket, required to be valid when
					/// BridgeSocketType is network::TlsSocket. The default context is a SSL context
					/// that has absolutely no configuration done to it, and rather simply serves as
					/// a placeholder for initially constructing a new SSL Stream object. The
					/// context is meant to always be swapped out with a valid SSL context once the
					/// TLS client hello has been parsed and the SNI host declaration is extracted
					/// during the initial client handshake. During this handshake, the in memory
					/// certificate store is consulted to either provide an existing context for the
					/// host the client requested, or, once the real certificate has been fetched
					/// upstream, spoof the certificate and return a server context built with the
					/// spoofed certificate to serve the client.
					/// </param>
					/// <param name="clientContext">
					/// A pointer to the default client context. Not required or used when
					/// BridgeSocketType is network::TcpSocket, required to be valid when
					/// BridgeSocketType is network::TlsSocket. The client context is managed by the
					/// acceptor, and is shared across all clients for the duration of the lifetime
					/// of the program, or object(s) responsible for generating proxy connections.
					/// The client context loads the cURL/Mozilla ca-bundle certificate list and
					/// uses this for verifying server certificates. In this context, the "client"
					/// is the proxy.
					/// </param>
					/// <param name="onInfoCb">
					/// A callback to receive generated information about general events. Data that
					/// may be sent through this callback, if provided, is simply "verbose" output
					/// from the general option of this class. Must be thread safe.
					/// </param>
					/// <param name="onWarnCb">
					/// A callback to receive generated information warning consumers about an event
					/// that the consumer wish to have insight into, but nothing critial. For
					/// example, if a stream times out, a warning would be raised when the timeout
					/// occurs. Must be thread safe.
					/// </param>
					/// <param name="onErrorCb">
					/// A callback to receive generated information regarding errors that occurred,
					/// but were handled. This class incorporates functionality spanning many
					/// external classes and libraries. All of these are capable of throwing. Given
					/// the nature of this object being in the middle of raw, unpredictable data,
					/// it's reasonable to expect errors. What's not reasonable is to throw and drop
					/// client connections every time one occurs. Most foreseable exceptions would
					/// occur as a direct result of our intervention, and the transaction is capable
					/// of continuing in the event of a failed attempt to manipulate intercepted
					/// data. Therefore, this class handles and continues. If this callback is
					/// supplied, in the event of an exception, the message of the exception will be supplied.
					/// 
					/// Consumers can inspect or log such events. Must be thread safe.
					/// </param>
					TlsCapableHttpBridge(
						boost::asio::io_service* service,						
						BaseInMemoryCertificateStore* certStore = nullptr,
						boost::asio::ssl::context* defaultServerContext = nullptr,
						boost::asio::ssl::context* clientContext = nullptr,
						util::cb::HttpMessageBeginCheckFunction onMessageBegin = nullptr,
						util::cb::HttpMessageEndCheckFunction onMessageEnd = nullptr,
						util::cb::MessageFunction onInfoCb = nullptr,
						util::cb::MessageFunction onWarnCb = nullptr,
						util::cb::MessageFunction onErrorCb = nullptr
						);

					/// <summary>
					/// No copy no move no thx.
					/// </summary>
					TlsCapableHttpBridge(const TlsCapableHttpBridge&) = delete;
					TlsCapableHttpBridge(TlsCapableHttpBridge&&) = delete;
					TlsCapableHttpBridge& operator=(const TlsCapableHttpBridge&) = delete;

					/// <summary>
					/// Default destructor.
					/// </summary>
					~TlsCapableHttpBridge()
					{

					}

				private:

					bool m_shouldTerminate = false;

					/// <summary>
					/// HTTP request object which is read from the connected client and written to
					/// the upstream host.
					/// </summary>
					std::unique_ptr<http::HttpRequest> m_request = nullptr;

					/// <summary>
					/// HTTP response object which is read from the upstream host and written to the
					/// downstream client.
					/// </summary>
					std::unique_ptr<http::HttpResponse> m_response = nullptr;

					/// <summary>
					/// Socket used to connect to the client's desired host.
					/// </summary>
					BridgeSocketType m_upstreamSocket;

					/// <summary>
					/// Socket used for connecting to the client.
					/// </summary>
					BridgeSocketType m_downstreamSocket;

					/// <summary>
					/// For ensuring that asynchronous operation callback handlers involving the
					/// upstream server connection are not concurrently executed.
					/// </summary>
					boost::asio::strand m_upstreamStrand;

					/// <summary>
					/// For ensuring that asynchronous operation callback handlers involving the
					/// downstream client connection are not concurrently executed.
					/// </summary>
					boost::asio::strand m_downstreamStrand;

					/// <summary>
					/// Used for resolving the target upstream server after it has been discovered
					/// from the client headers or TLS hello.
					/// </summary>
					boost::asio::ip::tcp::resolver m_resolver;					

					/// <summary>
					/// To prevent asynchronous operations from hanging forever. This should be
					/// reset with a specific timeout every time a new asynchrous operation is
					/// initiated, and also when completed. The idea is that you must keep the timer
					/// spinning beyond the previously set timeout, because once the timeout is
					/// reached, the completion handler for the timeout will be invoked which will
					/// cause the bridge to be terminated.
					/// </summary>
					boost::asio::deadline_timer m_streamTimer;					

					/// <summary>
					/// Pointer to the in memory certificate store that is required for TLS
					/// connections, to fetch and or generate certificates and corresponding server
					/// contexts as needed.
					/// </summary>
					BaseInMemoryCertificateStore* m_certStore;

					util::cb::HttpMessageBeginCheckFunction m_onMessageBegin;
					util::cb::HttpMessageEndCheckFunction m_onMessageEnd;

					/// <summary>
					/// Member that is to be set whenever the upstream certificate verification
					/// callback method is invoked. This member is held, then used to request the in
					/// memory certificate store to spoof and create a new context based on this
					/// verified, real certificate.
					/// </summary>
					X509* m_upstreamCert = nullptr;

					/// <summary>
					/// Stores the current host whenever a new request is processed by the bridge.
					/// For every subsequent request, the host information in the request headers is
					/// compared to the host we presently have an upstream connection with. If the
					/// new request host does not match, the bridge is terminated.
					/// </summary>
					std::string m_upstreamHost;		

					/// <summary>
					/// Stores the port number on the remote host that the bridge is supposed to be
					/// holding a connection to. This is important, because host:80 and host:8080
					/// are obviously not the same. Since we're agnostic to how packets get
					/// forwarded to us at this scope, we cannot assume that every plain TCP client
					/// wants port 80, and we cannot assume that every encrypted TLS client wants
					/// port 443. When headers are parsed, port information can be included, and
					/// this must be removed from the m_upstreamHost string, parsed and stored in
					/// this member.
					/// </summary>
					uint16_t m_upstreamHostPort = 0;

					/// <summary>
					/// Googled latest RFC, got 6066, ctrl+f "maximum", got section 4, says 2^14
					/// bytes. There is an extension that allows negotiation of the max length, but
					/// the server "MAY" acknowledge it. Since we act as the server, and since the
					/// RFC doesn't demand that servers respect this extension, we "MAY" just not care.
					/// 
					/// Besides, this buffer is just to ensure we can peek read the portion of the
					/// TLS client hello to discover the SNI extension and extract the value. If our
					/// buffer is too small, it's only a peek read anyway, so we're not going to
					/// hurt anything by not having enough room for the entire handshake data.
					/// </summary>
					static constexpr size_t TlsPeekBufferSize = 16384;


					/// <summary>
					/// The mechanism provided in openSSL for parsing the TLS client hello and
					/// extracting the host name from the SNI extension is extraordinarily
					/// cumbersome. It forces us to work within a static context (callback), and the
					/// callback and callback data pointer are context-bound, rather than
					/// stream-bound. So, we would have to bind this callback and arguments to the
					/// global, default SSL server context. How can we accurately serve on a
					/// per-connection basis with such a context? Perhaps it's because we're not
					/// acting as a single server, but rather every single server.
					/// 
					/// To avoid the gymnastics of this mechanism, we do a ::peek read on new TLS
					/// clients as soon as they connect, and then manually parse the TLS SNI
					/// extension from the read data, extracting the desired host. This allows us to
					/// both remain within our closed bridge context, and fetch upstream
					/// certificates before initiating the downstream handshake process. So before a
					/// client even gets to deliver the TLS client hello, we already know precisely
					/// which server the client is seeking and have the context prepared to initiate
					/// the handshake without switching contexts mid-handshake.
					/// 
					/// Props to Dustin Lundquist, who dissected the hello and SNI and posted the data
					/// here: http://stackoverflow.com/a/21926971/562566, and put it to use in his
					/// SNI proxy, here: https://github.com/dlundquist/sniproxy. While none of his
					/// code is used, the detailed diagram of the payload structure was key to the
					/// implementation here.
					/// 
					/// This of course is only ever used in the case that BridgeSocketType is
					/// network::TlsSocket, hence the unique_ptr so it's not wastefully allocated on
					/// non-tls bridges.
					/// </summary>
					std::unique_ptr< std::array<char, TlsPeekBufferSize> > m_tlsPeekBuffer = nullptr;

					/// <summary>
					/// Tells the minimum length that a peek read must be in order to even reach
					/// the extensions area of a potentially accurate TLS client hello.
					/// </summary>
					static constexpr size_t MinTlsHelloLength = 43;

					/// <summary>
					/// Used for extracting certificate name information on certificates passing
					/// through the verification phase.
					/// </summary>
					static constexpr size_t MaxDomainNameSize = 1000;

					/// <summary>
					/// Indicates whether or not ::Kill() has already successfully run and initiated the shutdown.
					/// </summary>
					bool m_killed = false;

					/// <summary>
					/// Since it's possible that two completion handlers on either side of the
					/// bridge may terminate by calling ::Kill() at the same time, or that the
					/// stream timer may expire, which is not synchronized through any handler, it's
					/// necessary to do some locking in the ::Kill() method to ensure that the
					/// shutdown sequence is only initiated once. This flag will be used as a
					/// spinlock to force this needed synchronization.
					/// </summary>
					std::atomic_flag m_killLock = ATOMIC_FLAG_INIT;	

					/// <summary>
					/// Indicates whether or not keep-alive should be used, at the client's request.
					/// </summary>
					bool m_keepAlive = true;

				public:

					/// <summary>
					/// It's necessary for HTTP and HTTPS listeners to have access to the underlying
					/// TCP socket, for the purpose of accepting clients to initiate a new
					/// transaction. This method uses template specialization in the in the source,
					/// as accessing the correct layer varies between socket types.
					/// </summary>
					/// <returns>
					/// The underlying TCP socket.
					/// </returns>
					boost::asio::ip::tcp::socket& DownstreamSocket();

					/// <summary>
					/// It's necessary for HTTP and HTTPS listeners to have access to the underlying
					/// TCP socket, for the purpose of accepting clients to initiate a new
					/// transaction. This method uses template specialization in the in the source,
					/// as accessing the correct layer varies between socket types.
					/// </summary>
					/// <returns>
					/// The underlying TCP socket.
					/// </returns>
					boost::asio::ip::tcp::socket& UpstreamSocket();

					/// <summary>
					/// Initiates the process of reading and writing between client and server.
					/// After this call, the bridge maintains its own lifecycle via shared_from_this
					/// passed to async method handlers.
					/// </summary>
					void Start();

				private:

					class PreviewParser
					{
						private:

							struct HeaderCbData
							{
								std::unordered_map<std::string, std::string> headers;
								std::string lastHeaderName;
								bool headersComplete;
							};

							bool m_headersComplete = false;

						public:

							enum class ParseResult
							{
								IsHttp,
								NotHttp,
								HttpWithUpgrade,
								Failure
							};

							const bool HeadersComplete() const
							{
								return m_headersComplete;
							}

							std::string errorMessage;

							const ParseResult Parse(const char* data, const size_t dataLength, std::string& outHost)
							{

								if (!data || dataLength == 0)
								{
									return ParseResult::Failure;
								}

								auto onBody = [](http_parser* parser, const char *at, size_t length)->int
								{
									return 0;
								};

								auto onChunkComplete = [](http_parser* parser)->int
								{
									return 0;
								};

								auto onChunkHeader = [](http_parser* parser)->int
								{
									return 0;
								};

								auto onHeadersComplete = [](http_parser* parser)->int
								{
									if (parser == nullptr)
									{
										// Failure. Somehow.
										return -1;
									}

									auto* data = static_cast<HeaderCbData*>(parser->data);
									if (data != nullptr)
									{
										data->headersComplete = true;
										return 0;
									}

									return -1;
								};

								auto onHeaderField = [](http_parser* parser, const char *at, size_t length)->int
								{
									if (parser == nullptr || at == nullptr || parser->data == nullptr)
									{
										// Failure. Somehow.
										return -1;
									}

									auto* data = static_cast<HeaderCbData*>(parser->data);
									if (data != nullptr)
									{
										data->lastHeaderName = std::string(at, length);
										return 0;
									}

									return -1;
								};

								auto onHeaderValue = [](http_parser* parser, const char *at, size_t length)->int
								{
									if (parser == nullptr || at == nullptr || parser->data == nullptr)
									{
										// Failure. Somehow.
										return -1;
									}

									auto* data = static_cast<HeaderCbData*>(parser->data);
									if (data != nullptr)
									{
										data->headers[data->lastHeaderName] = std::string(at, length);
										return 0;
									}

									return -1;
								};

								auto onUrl = [](http_parser* parser, const char *at, size_t length)->int
								{
									return 0;
								};

								auto onMessageBegin = [](http_parser* parser)->int
								{
									return 0;
								};

								auto onMessageComplete = [](http_parser* parser)->int
								{
									return 0;
								};

								http_parser_settings parserSettings;

								parserSettings.on_body = onBody;
								parserSettings.on_chunk_complete = onChunkComplete;
								parserSettings.on_chunk_header = onChunkHeader;
								parserSettings.on_headers_complete = onHeadersComplete;
								parserSettings.on_header_field = onHeaderField;
								parserSettings.on_header_value = onHeaderValue;
								parserSettings.on_message_begin = onMessageBegin;
								parserSettings.on_message_complete = onMessageComplete;
								parserSettings.on_status = onUrl;
								parserSettings.on_url = onUrl;

								http_parser* parser;
								parser = static_cast<http_parser*>(malloc(sizeof(http_parser)));

								if (!parser)
								{
									return ParseResult::Failure;
								}

								http_parser_init(parser, HTTP_REQUEST);

								HeaderCbData parserData;
								parser->data = &parserData;

								auto nparsed = http_parser_execute(parser, &parserSettings, data, dataLength);

								// Set the host before we leave.
								auto host = parserData.headers.find(util::http::headers::Host);
								if (host != parserData.headers.end())
								{
									outHost = host->second;
								}

								m_headersComplete = parserData.headersComplete;

								if (parser->upgrade == 1)
								{
									free(parser);
									if (outHost.size() == 0)
									{
										// Most definitely should not be empty.
										return ParseResult::Failure;
									}

									return ParseResult::HttpWithUpgrade;
								}

								if (parser->http_errno != 0)
								{	
									errorMessage = std::string(u8"In ParseResult::Parse(...) -Got http_parser error: ");
									errorMessage.append(http_errno_description(HTTP_PARSER_ERRNO(parser)));									
									
									if (parser->http_errno == HPE_INVALID_METHOD || parser->http_errno == HPE_UNKNOWN)
									{
										free(parser);
										return ParseResult::NotHttp;
									}
								}

								if (outHost.size() == 0)
								{
									free(parser);
									// Most definitely should not be empty.
									return ParseResult::Failure;
								}

								free(parser);
								return ParseResult::IsHttp;
							}							
					};

					/// <summary>
					/// Initiates shutdown of all pending asynchronous operations, which will
					/// eventually lead to the destruction of this object once all pending handlers
					/// return, releasing the shared_ptrs each of them have obtained.
					/// 
					/// Since it's possible for multiple concurrent handlers to call this method,
					/// functionality is protected with a spinlock and a bool flag which indicates
					/// if the shutdown process has already been started or not. This way, we don't
					/// have multiple concurrent or even sequential threads calling shutdown and
					/// cancel on members running on the io_service.
					/// </summary>
					void Kill()
					{
						while (m_killLock.test_and_set(std::memory_order_acquire))
						{
							cpu_relax();
						}					

						if (!m_killed)
						{

							#ifndef NDEBUG
							ReportInfo(u8"TlsCapableHttpBridge<>::Kill");
							#endif // !NDEBUG

							// This will force any pending async operations to stop and their completion
							// handlers to be called with operation_aborted as the error code.
							
							// XXX TODO - Perhaps we should use ReportWarning here instead of ReportError,
							// since the kinds of errors you usually get from these calls are non-fatal
							// issues. Usually just complaints about state etc.

							boost::system::error_code downstreamCancelErr;
							boost::system::error_code downstreamShutdownErr;
							boost::system::error_code downstreamCloseErr;	
							boost::system::error_code upstreamCancelErr;
							boost::system::error_code upstreamShutdownErr;
							boost::system::error_code upstreamCloseErr;

							this->m_resolver.cancel();							

							this->DownstreamSocket().cancel(downstreamCancelErr);
							this->DownstreamSocket().shutdown(boost::asio::socket_base::shutdown_both, downstreamShutdownErr);
							this->DownstreamSocket().close(downstreamCloseErr);

							this->UpstreamSocket().cancel(upstreamCancelErr);
							this->UpstreamSocket().shutdown(boost::asio::socket_base::shutdown_both, upstreamShutdownErr);
							this->UpstreamSocket().close(upstreamCloseErr);

							// Force cancel any async waiting of the timer.
							SetInfiniteStreamTimeout();

							if (downstreamShutdownErr)
							{
								/*
								These errors are super annoying and offer little to no insight.

								std::string err(u8"In TlsCapableHttpBridge<BridgeSocketType>::Kill() - When shutting down downstream socket, got error:\t");
								err.append(downstreamShutdownErr.message());
								ReportError(err);
								*/
							}

							if (downstreamCloseErr)
							{
								/*
								These errors are super annoying and offer little to no insight.

								std::string err(u8"In TlsCapableHttpBridge<BridgeSocketType>::Kill() - When closing downstream socket, got error:\t");
								err.append(downstreamCloseErr.message());
								ReportError(err);
								*/
							}

							if (upstreamShutdownErr)
							{
								/*
								These errors are super annoying and offer little to no insight.

								std::string dErrMessage(u8"In TlsCapableHttpBridge<BridgeSocketType>::Kill() - When shutting down upstream socket, got error:\t");
								dErrMessage.append(upstreamShutdownErr.message());
								ReportError(dErrMessage);
								*/
							}

							if (upstreamCloseErr)
							{
								/*
								These errors are super annoying and offer little to no insight.

								std::string err(u8"In TlsCapableHttpBridge<BridgeSocketType>::Kill() - When closing upstream socket, got error:\t");
								err.append(upstreamCloseErr.message());
								ReportError(err);
								*/
							}

							m_killed = true;
						}

						m_killLock.clear(std::memory_order_release);
					}

					/// <summary>
					/// Completion handler for when the DNS resolution for the desired upstream host
					/// has completed. This method is specialized, because when dealing with a
					/// secure client, before initiating the upstream connection, we want to set the
					/// SNI hostname entry on the socket.
					/// 
					/// In the event that this operation was a failure, meaning that the supplied
					/// error parameter was set and the code was one unexpected, the bridge will be 
					/// terminated.
					/// </summary>
					/// <param name="error">
					/// Error code that will indicate if any errors were handled during the async
					/// operation, providing details if an error did occur and was handled.
					/// </param>
					/// <param name="endpointIterator">
					/// Returned enpoint iterator, populated with addresses from returned A record
					/// entries during the resolution process. The endpoints are preconfigured with
					/// address and port number, as the "service" parameter for the resolver is
					/// used. The port numbers configured correspond to the supplied service during
					/// resolution. "http" == port 80, "https" == port 443, etc.
					/// </param>
					void OnResolve(const boost::system::error_code& error, boost::asio::ip::tcp::resolver::iterator endpointIterator);

					/// <summary>
					/// Completion handler for when the asynchronous operation of establishing a
					/// socket connection to a the resolved upstream host has returned. This method
					/// is specialized, because when dealing with a secure client, the order of
					/// operations varies from a regular TCP/HTTP client. With a secure client, once
					/// a connection is established, a handshake with the connected remote upstream
					/// peer must take place, at which time the remote server's certificate will be
					/// verified, and if verified spoofed, the a downstream client handshake will
					/// occur. After all this, the client's request headers will be read, then
					/// written upstream.
					/// 
					/// In the case of a regular TCP/HTTP client, the process on upstream connect
					/// simply jumps immediately to writing the client's request data to the server,
					/// then fetching a response from the server.
					/// 
					/// In the event that this operation was a failure, meaning that the supplied
					/// error parameter was set and the code was one unexpected, the bridge will be 
					/// terminated.
					/// </summary>
					/// <param name="error">
					/// Error code that will indicate if any errors were handled during the async
					/// operation, providing details if an error did occur and was handled.
					/// </param>
					void OnUpstreamConnect(const boost::system::error_code& error);

					/// <summary>
					/// Completion handler for when the initial asynchronous read from the upstream
					/// server is complete. The initial read specifies a condition that indicates
					/// that reading into the buffer should be paused, and this handler should be
					/// called with the data that has been written to the buffer up until the
					/// discovery of the completion condition parameters. In our case, the condition
					/// is that the header terminating CRLF has been discovered in the supplied read buffer.
					/// 
					/// Note that such async_read_until methods can and usually do read data beyond
					/// the specified completion condition. In our case, this means that the read
					/// buffer will most likely not just contain HTTP headers, but will also contain
					/// a small portion of the response body as well, if there is one. The
					/// bytesTransferred member **will not** accurately reflect this information.
					/// Instead, it will return how many bytes were read before and including the
					/// bytes that make up the completion condition.
					/// 
					/// So again, in our case, the bytesTransferred member will be set to the total
					/// size of the response headers, plus the terminating CRLF. Interally, the
					/// ::Parse() method(s) of the HttpResponse and HttpRequest classes will take
					/// the bytesTransferred as an argument, and then do a comparison of this
					/// number against the true size of the variable-length streambuf read buffer,
					/// and separate the header and payload data correctly. It is therefore of the
					/// utmost importance to handle this parameter value correctly.
					/// 
					/// In the event that this operation was a failure, meaning that the supplied
					/// error parameter was set and the code was one unexpected, the bridge will be 
					/// terminated.
					/// </summary>
					/// <param name="error">
					/// Error code that will indicate if any errors were handled during the async
					/// operation, providing details if an error did occur and was handled.
					/// </param>
					/// <param name="bytesTransferred">
					/// The amount of data read into the buffer up until the discovery of the
					/// specified completion condition, plus the size of the bytes that make up the
					/// completion condition. Does not accurately represent the total data read from
					/// the remote peer.
					/// </param>
					void OnUpstreamHeaders(const boost::system::error_code& error, const size_t bytesTransferred)
					{

						#ifndef NDEBUG
						ReportInfo(u8"TlsCapableHttpBridge::OnUpstreamHeaders");
						#endif // !NDEBUG

						if (m_shouldTerminate)
						{
							// The session was flagged to be killed AFTER this write completes.
							// Exit. This only happens when one end of the connection closed
							// during a read, but we got data to send to the other end before
							// this happened.
							Kill();
							return;
						}

						// EOF doesn't necessarily mean something critical happened. Could simply be
						// that we got the entire valid response, and the server closed the connection
						// after.
						if ((!error || (error == boost::asio::error::eof || (error.category() == boost::asio::error::get_ssl_category()) && (ERR_GET_REASON(error.value()) == SSL_R_SHORT_READ))))
						{
							bool closeAfter = (error == boost::asio::error::eof) || ((error.category() == boost::asio::error::get_ssl_category()) && (ERR_GET_REASON(error.value()) == SSL_R_SHORT_READ));
							bool wasSslShortRead = ((error.category() == boost::asio::error::get_ssl_category()) && (ERR_GET_REASON(error.value()) == SSL_R_SHORT_READ));

							if (closeAfter)
							{
								m_shouldTerminate = true;
							}

							if (m_response->Parse(bytesTransferred))
							{
								if (wasSslShortRead && (!m_response->IsPayloadComplete() || !m_response->HeadersComplete()))
								{
									// This is a security threat if WE TREAT THIS LIKE IT'S NORMAL.

									// If wasSslShortRead == true, but the payload is deemed complete, then
									// we simply have a dumb server that didn't do a clean TLS shutdown.
									ReportInfo(u8"In TlsCapableHttpBridge::OnUpstreamHeaders(const boost::system::error_code&, const size_t) - Got TLS short read and payload IS NOT complete. Aborting.");
									Kill();
									return;
								}

								if (wasSslShortRead)
								{
									ReportWarning(u8"In TlsCapableHttpBridge::OnUpstreamHeaders(const boost::system::error_code&, const size_t) - Got TLS short read, but payload is complete. The naughty server did not do a proper TLS shutdown.");
								}

								if (!closeAfter && !m_response->HeadersComplete())
								{
									boost::asio::async_read(
										m_upstreamSocket,
										m_response->GetReadBuffer(),
										boost::asio::transfer_at_least(1),
										m_upstreamStrand.wrap(
											std::bind(
												&TlsCapableHttpBridge::OnUpstreamHeaders,
												shared_from_this(),
												std::placeholders::_1,
												std::placeholders::_2
											)
										)
									);

									return;
								}

								// We only bother to check if the response should be blocked
								// if the request has not been whitelisted.
								if (m_request->GetShouldBlock() > -1)
								{
									auto shouldBlockResponse = ShouldBlockTransaction(m_request.get(), m_response.get());

									if (shouldBlockResponse)
									{
										m_request->SetShouldBlock(1);
										auto responseBuffer = m_request->GetWriteBuffer();

										boost::asio::async_write(
											m_downstreamSocket,
											responseBuffer,
											boost::asio::transfer_all(),
											m_downstreamStrand.wrap(
												std::bind(
													&TlsCapableHttpBridge::OnDownstreamWrite,
													shared_from_this(),
													std::placeholders::_1
												)
											)
										);

										return;
									}
								}

								// We want to remove any header that has to do with Google's SDHC
								// compression method. We don't want it, because we don't support it
								// so we'd have no way to handle content compressed with this method.
								m_response->RemoveHeader(util::http::headers::GetDictionary);

								// Ensure that nobody is advertising for QUIC support.
								m_response->RemoveHeader(util::http::headers::AlternateProtocol);

								// Sigh, also remove declaration of any alternative protocol
								m_response->RemoveHeader(util::http::headers::AltSvc);

								// Firefox developers are bunch of double talking liars, and claim that you
								// can disable public key pinning. However, for their buddies who must
								// pay them off or something, this isn't true. It's enforced no matter
								// what do you. So what's the solution? We strip the headers from
								// the client altogether.
								m_response->RemoveHeader(util::http::headers::PublicKeyPins);
								m_response->RemoveHeader(util::http::headers::PublicKeyPinsReportOnly);

								// Set m_keepAlive to what the server has specified. The client may have requested it, but
								// ultimately it's up to the server how it's going to serve us.
								auto connectionHeader = m_response->GetHeader(util::http::headers::Connection);

								bool keepAlive = false;

								if (m_request->GetHttpVersion() != http::HttpProtocolVersion::HTTP1)
								{
									keepAlive = true;
								}								

								while (connectionHeader.first != connectionHeader.second)
								{
									if (connectionHeader.first->second.compare(u8"close") == 0)
									{
										keepAlive = false;										
									}
									++connectionHeader.first;
								}

								m_keepAlive = keepAlive;								

								if (!closeAfter && m_response->IsPayloadComplete() == false && m_response->GetConsumeAllBeforeSending() == true)
								{
									// We need to reinitiate sequential reads of the response
									// payload until we have all of the response body, as it has
									// been marked for inspection.

									// We do this in a try/catch because getting the read buffer for the payload
									// can throw if the maximum payload size has been reached. This is defined as
									// a constexpr in BaseHttpTransaction. 
									try
									{
										auto readBuffer = m_response->GetReadBuffer();

										SetStreamTimeout(boost::posix_time::minutes(5));

										boost::asio::async_read(
											m_upstreamSocket,
											readBuffer,
											boost::asio::transfer_at_least(1),
											m_upstreamStrand.wrap(
												std::bind(
													&TlsCapableHttpBridge::OnUpstreamRead,
													shared_from_this(),
													std::placeholders::_1,
													std::placeholders::_2
													)
												)
											);

										return;
									}
									catch (std::exception& e)
									{
										ReportError(e.what());
									}									
								}
								else
								{
									// We need to write what we have to the client.

									SetStreamTimeout(boost::posix_time::minutes(5));

									auto writeBuffer = m_response->GetWriteBuffer();

									boost::asio::async_write(
										m_downstreamSocket,
										writeBuffer,
										boost::asio::transfer_all(),
										m_downstreamStrand.wrap(
											std::bind(
												&TlsCapableHttpBridge::OnDownstreamWrite,
												shared_from_this(),
												std::placeholders::_1
												)
											)
										);

									return;
								}								
							}
							else
							{
								ReportError(u8"In TlsCapableHttpBridge::OnUpstreamHeaders(const boost::system::error_code&, const size_t) - Failed to parse response.");
							}							
						}

						if (error)
						{
							std::string errMsg(u8"In TlsCapableHttpBridge::OnUpstreamHeaders(const boost::system::error_code&, const size_t) - Got error:\t");
							errMsg.append(error.message());
							ReportError(errMsg);
						}

						Kill();
					}

					/// <summary>
					/// Completion handler for when an asynchronous read of the response payload
					/// from the upstream server completes. Requests the response payload to be
					/// parsed and, depending on configured options, may write the data to the
					/// client, or resize the read buffer and continue reading the response payload
					/// until completion.
					/// 
					/// In the event that this operation was a failure, meaning that the supplied
					/// error parameter was set and the code was one unexpected, the bridge will be 
					/// terminated.
					/// </summary>
					/// <param name="error">
					/// Error code that will indicate if any errors were handled during the async
					/// operation, providing details if an error did occur and was handled.
					/// </param>
					/// <param name="bytesTransferred">
					/// The number of bytes read from the remote upstream server.
					/// </param>
					void OnUpstreamRead(const boost::system::error_code& error, const size_t bytesTransferred)
					{
						#ifndef NDEBUG
						ReportInfo(u8"TlsCapableHttpBridge::OnUpstreamRead");
						#endif // !NDEBUG

						if (m_shouldTerminate)
						{
							// The session was flagged to be killed AFTER this write completes.
							// Exit. This only happens when one end of the connection closed
							// during a read, but we got data to send to the other end before
							// this happened.
							Kill();
							return;
						}

						// EOF doesn't necessarily mean something critical happened. Could simply be
						// that we got the entire valid response, and the server closed the connection
						// after.
						if ((!error || (error == boost::asio::error::eof || (error.category() == boost::asio::error::get_ssl_category()) && (ERR_GET_REASON(error.value()) == SSL_R_SHORT_READ))))
						{
							bool closeAfter = (error == boost::asio::error::eof) || ((error.category() == boost::asio::error::get_ssl_category()) && (ERR_GET_REASON(error.value()) == SSL_R_SHORT_READ));
							bool wasSslShortRead = ((error.category() == boost::asio::error::get_ssl_category()) && (ERR_GET_REASON(error.value()) == SSL_R_SHORT_READ));

							if (closeAfter)
							{
								m_shouldTerminate = true;
							}

							if (m_response->Parse(bytesTransferred))
							{
								if (wasSslShortRead && (!m_response->IsPayloadComplete() || !m_response->HeadersComplete()))
								{
									// This is a security threat if WE TREAT THIS LIKE IT'S NORMAL.

									// If wasSslShortRead == true, but the payload is deemed complete, then
									// we simply have a dumb server that didn't do a clean TLS shutdown.
									ReportInfo(u8"In TlsCapableHttpBridge::OnUpstreamRead(const boost::system::error_code&, const size_t) - Got TLS short read and payload IS NOT complete. Aborting.");
									Kill();
									return;
								}

								if (wasSslShortRead)
								{
									ReportWarning(u8"In TlsCapableHttpBridge::OnUpstreamRead(const boost::system::error_code&, const size_t) - Got TLS short read, but payload is complete. The naughty remote server did not do a proper TLS shutdown.");
								}

								if (m_request->GetShouldBlock() > -1 && m_response->IsPayloadComplete() && m_response->GetConsumeAllBeforeSending())
								{
									// Response was flagged for further inspection. Supply to ShouldBlock...
									auto shouldBlock = ShouldBlockTransaction(m_request.get(), m_response.get());

									if (shouldBlock)
									{	
										m_request->SetShouldBlock(1);
										auto responseBuffer = m_request->GetWriteBuffer();

										boost::asio::async_write(
											m_downstreamSocket,
											responseBuffer,
											boost::asio::transfer_all(),
											m_downstreamStrand.wrap(
												std::bind(
													&TlsCapableHttpBridge::OnDownstreamWrite,
													shared_from_this(),
													std::placeholders::_1
												)
											)
										);

										return;
									}
								}
								
								if (!closeAfter && m_response->IsPayloadComplete() == false && m_response->GetConsumeAllBeforeSending() == true)
								{
									SetStreamTimeout(boost::posix_time::minutes(5));

									try
									{
										auto readBuffer = m_response->GetReadBuffer();

										boost::asio::async_read(
											m_upstreamSocket,
											readBuffer,
											boost::asio::transfer_at_least(1),
											m_upstreamStrand.wrap(
												std::bind(
													&TlsCapableHttpBridge::OnUpstreamRead,
													shared_from_this(),
													std::placeholders::_1,
													std::placeholders::_2
													)
												)
											);

										return;
									}
									catch (std::exception& e)
									{
										std::string errMsg(u8"In TlsCapableHttpBridge::OnUpstreamRead(const boost::system::error_code&, const size_t) - Got error:\t");
										errMsg.append(e.what());
										ReportError(errMsg);
										Kill();
										return;
									}
								}
								
								// Simply write what we've got to the client.
								auto writeBuffer = m_response->GetWriteBuffer();

								boost::asio::async_write(
									m_downstreamSocket,
									writeBuffer,
									boost::asio::transfer_all(),
									m_downstreamStrand.wrap(
										std::bind(
											&TlsCapableHttpBridge::OnDownstreamWrite,
											shared_from_this(),
											std::placeholders::_1
											)
										)
									);

								return;
							}
							else
							{
								ReportError(u8"In TlsCapableHttpBridge::OnUpstreamRead(const boost::system::error_code&, const size_t) - Failed to parse response.");
							}
						}
						
						if (error)
						{
							std::string errMsg(u8"In TlsCapableHttpBridge::OnUpstreamRead(const boost::system::error_code&, const size_t) - Got error:\t");
							errMsg.append(error.message());
							
#ifndef NDEBUG
							errMsg.append("\tcat name: ");
							errMsg.append(error.category().name());
							errMsg.append("\terr val: ");
							errMsg.append(std::to_string(error.value()));
							errMsg.append("\terr reason: ");
							errMsg.append(std::to_string(ERR_GET_REASON(error.value())));
							errMsg.append("\tbytes trans: ");
							errMsg.append(std::to_string(bytesTransferred));
#endif

							ReportError(errMsg);
						}

						Kill();
					}

					/// <summary>
					/// Completion handler for when an asynchronous write of either headers or
					/// request payload data has finished being written to the upstream server.
					/// 
					/// In the event that this operation was a failure, meaning that the supplied
					/// error parameter was set and the code was one unexpected, the bridge will be 
					/// terminated.
					/// </summary>
					/// <param name="error">
					/// Error code that will indicate if any errors were handled during the async
					/// operation, providing details if an error did occur and was handled.
					/// </param>
					void OnUpstreamWrite(const boost::system::error_code& error)
					{

						#ifndef NDEBUG
						ReportInfo(u8"TlsCapableHttpBridge::OnUpstreamWrite");
						#endif // !NDEBUG

						if (m_shouldTerminate)
						{
							// The session was flagged to be killed AFTER this write completes.
							// Exit. This only happens when one end of the connection closed
							// during a read, but we got data to send to the other end before
							// this happened.
							Kill();
							return;
						}
						
						if (!error)
						{
							if (m_request->IsPayloadComplete() == false)
							{
								// The client has more to write to the server.

								SetStreamTimeout(boost::posix_time::minutes(5));

								try
								{
									auto readBuffer = m_request->GetReadBuffer();

									boost::asio::async_read(
										m_downstreamSocket,
										readBuffer,
										boost::asio::transfer_at_least(1),
										m_downstreamStrand.wrap(
											std::bind(
												&TlsCapableHttpBridge::OnDownstreamRead,
												shared_from_this(),
												std::placeholders::_1,
												std::placeholders::_2
												)
											)
										);

									return;
								}
								catch (std::exception& e)
								{
									std::string errMsg(u8"In TlsCapableHttpBridge::OnUpstreamWrite(const boost::system::error_code&) - Got error:\t");
									errMsg.append(e.what());
									ReportError(errMsg);
								}
							}
							else
							{
								// Client is all done, get the response headers.

								SetStreamTimeout(boost::posix_time::minutes(5));

								boost::asio::async_read(
									m_upstreamSocket,
									m_response->GetReadBuffer(), 
									boost::asio::transfer_at_least(1),
									m_upstreamStrand.wrap(
										std::bind(
											&TlsCapableHttpBridge::OnUpstreamHeaders, 
											shared_from_this(), 
											std::placeholders::_1,
											std::placeholders::_2
											)
										)
									);

								return;
							}
						}
						else
						{
							std::string errMsg(u8"In TlsCapableHttpBridge::OnUpstreamWrite(const boost::system::error_code&) - Got error:\t");
							errMsg.append(error.message());
							ReportError(errMsg);
						}

						Kill();
					}

					/// <summary>
					/// Completion handler for when the initial asynchronous read from the connected
					/// client is complete. The initial read specifies a condition that indicates
					/// that reading into the buffer should be paused, and this handler should be
					/// called with the data that has been written to the buffer up until the
					/// discovery of the completion condition parameters. In our case, the condition
					/// is that the header terminating CRLF has been discovered in the supplied read buffer.
					/// 
					/// Note that such async_read_until methods can and usually do read data beyond
					/// the specified completion condition. In our case, this means that the read
					/// buffer will most likely not just contain HTTP headers, but will also contain
					/// a small portion of the request body as well, if there is one. The
					/// bytesTransferred member **will not** accurately reflect this information.
					/// Instead, it will return how many bytes were read before and including the
					/// bytes that make up the completion condition.
					/// 
					/// So again, in our case, the bytesTransferred member will be set to the total
					/// size of the request headers, plus the terminating CRLF. Interally, the
					/// ::Parse() method(s) of the HttpResponse and HttpRequest classes will take
					/// the bytesTransferred as an argument, and then do a comparison of this
					/// number against the true size of the variable-length streambuf read buffer,
					/// and separate the header and payload data correctly. It is therefore of the
					/// utmost importance to handle this parameter value correctly.
					/// 
					/// In the event that this operation was a failure, meaning that the supplied
					/// error parameter was set and the code was one unexpected, the bridge will be 
					/// terminated.
					/// </summary>
					/// <param name="error">
					/// Error code that will indicate if any errors were handled during the async
					/// operation, providing details if an error did occur and was handled.
					/// </param>
					/// <param name="bytesTransferred">
					/// The amount of data read into the buffer up until the discovery of the
					/// specified completion condition, plus the size of the bytes that make up the
					/// completion condition. Does not accurately represent the total data read from
					/// the remote peer.
					/// </param>
					void OnDownstreamHeaders(const boost::system::error_code& error, const size_t bytesTransferred)
					{
						#ifndef NDEBUG
						ReportInfo(u8"TlsCapableHttpBridge::::OnDownstreamHeaders");
						#endif // !NDEBUG

						if (m_shouldTerminate)
						{
							// The session was flagged to be killed AFTER this write completes.
							// Exit. This only happens when one end of the connection closed
							// during a read, but we got data to send to the other end before
							// this happened.
							Kill();
							return;
						}

						// EOF doesn't necessarily mean something critical happened. Could simply be
						// that we got the entire valid response, and the server closed the connection
						// after.
						if ((!error || (error == boost::asio::error::eof || (error.category() == boost::asio::error::get_ssl_category()) && (ERR_GET_REASON(error.value()) == SSL_R_SHORT_READ))))
						{
							bool closeAfter = (error == boost::asio::error::eof) || ((error.category() == boost::asio::error::get_ssl_category()) && (ERR_GET_REASON(error.value()) == SSL_R_SHORT_READ));
							bool wasSslShortRead = ((error.category() == boost::asio::error::get_ssl_category()) && (ERR_GET_REASON(error.value()) == SSL_R_SHORT_READ));

							if (closeAfter)
							{
								m_shouldTerminate = true;
							}

							if (m_request->Parse(bytesTransferred))
							{			

								if (wasSslShortRead && (!m_request->IsPayloadComplete() || !m_request->HeadersComplete()))
								{
									// This is a security threat if WE TREAT THIS LIKE IT'S NORMAL.

									// If wasSslShortRead == true, but the payload is deemed complete, then
									// we simply have a dumb server that didn't do a clean TLS shutdown.
									ReportInfo(u8"In TlsCapableHttpBridge::OnDownstreamHeaders(const boost::system::error_code&, const size_t) - Got TLS short read and payload IS NOT complete. Aborting.");
									Kill();
									return;
								}

								if (wasSslShortRead)
								{
									ReportWarning(u8"In TlsCapableHttpBridge::OnDownstreamHeaders(const boost::system::error_code&, const size_t) - Got TLS short read, but payload is complete. The naughty client did not do a proper TLS shutdown.");
								}

								if (!closeAfter && !m_request->HeadersComplete())
								{
									boost::asio::async_read(
										m_downstreamSocket,
										m_request->GetReadBuffer(),
										boost::asio::transfer_at_least(1),
										m_downstreamStrand.wrap(
											std::bind(
												&TlsCapableHttpBridge::OnDownstreamHeaders,
												shared_from_this(),
												std::placeholders::_1,
												std::placeholders::_2
											)
										)
									);

									return;
								}

								
								auto shouldBlockRequest = ShouldBlockTransaction(m_request.get());

								if (shouldBlockRequest)
								{
									// If should-block was set here, then that means the request 
									// has already been set externally with a response buffer for
									// the request, because it was blocked immediately. Just go
									// ahead and write this back down to the client and then exit.
									auto responseBuffer = m_request->GetWriteBuffer();

									boost::asio::async_write(
										m_downstreamSocket,
										responseBuffer,
										boost::asio::transfer_all(),
										m_downstreamStrand.wrap(
											std::bind(
												&TlsCapableHttpBridge::OnDownstreamWrite,
												shared_from_this(),
												std::placeholders::_1
											)
										)
									);
									return;
								}

								// This little business is for dealing with browsers like Chrome, who just have
								// to use their own "I'm too cool for skool" compression methods like SDHC. We
								// want to be sure that we get normal, non-hipster encoded, non-organic smoothie
								// encoded reponses that sane people can decompress. So we just always replace
								// the Accept-Encoding header with this.
								std::string standardEncoding(u8"gzip");
								m_request->AddHeader(util::http::headers::AcceptEncoding, standardEncoding);

								// Modifying content-encoding isn't enough for that sweet organic spraytanned
								// browser Chrome and its server cartel buddies. If these special headers make
								// it through, even though we've explicitly defined our accepted encoding,
								// you're still going to get SDHC encoded data.
								m_request->RemoveHeader(util::http::headers::XSDHC);
								m_request->RemoveHeader(util::http::headers::AvailDictionary);
								
								// Ensure that nobody is advertising for QUIC support.
								m_request->RemoveHeader(util::http::headers::AlternateProtocol);

								// Sigh, also remove declaration of any alternative protocol.
								m_request->RemoveHeader(util::http::headers::AltSvc);

								// Firefox developers are bunch of double talking liars, and claim that you
								// can disable public key pinning. However, for their buddies who must
								// pay them off or something, this isn't true. It's enforced no matter
								// what do you. So what's the solution? We strip the headers from
								// the client altogether.
								m_request->RemoveHeader(util::http::headers::PublicKeyPins);
								m_request->RemoveHeader(util::http::headers::PublicKeyPinsReportOnly);

								auto hostHeader = m_request->GetHeader(util::http::headers::Host);

								if (hostHeader.first != hostHeader.second)
								{
									auto hostWithoutPort = hostHeader.first->second;

									boost::trim(hostWithoutPort);

									auto portInd = hostWithoutPort.find(':');

									if (portInd != std::string::npos && portInd < hostWithoutPort.size())
									{
										auto portString = hostWithoutPort.substr(portInd + 1);

										hostWithoutPort = hostWithoutPort.substr(0, portInd);

										try
										{
											m_upstreamHostPort = static_cast<uint16_t>(std::stoi(portString));
										}
										catch (...)
										{
											// We don't really care what went wrong. We failed to parse the port in the host. We'll
											// simply issue a warning, and assume port 80.
											ReportWarning(u8"In TlsCapableHttpBridge::OnDownstreamHeaders(const boost::system::error_code&, const size_t) - Failed to parse port in host entry. Assuming port 80.");
										}										
									}

									// If the we're already connected to a host and it's not the same, just quit.
									bool needsResolve = true;
									if (m_upstreamHost.size() > 0)
									{
										auto hostComparison = hostWithoutPort.compare(m_upstreamHost);
										
										if (hostComparison != 0)
										{
											Kill();
											return;
										}

										needsResolve = false;
									}

									if (needsResolve)
									{
										// If we're not already connected to a host, then we need to resolve it and
										// connect to it. This **should** only ever be true in the event that its a 
										// non-TLS (plain HTTP) connection.
										SetStreamTimeout(boost::posix_time::minutes(5));

										m_upstreamHost = hostWithoutPort;
										boost::asio::ip::tcp::resolver::query query(m_upstreamHost, std::is_same<BridgeSocketType, network::TlsSocket>::value ? "https" : "http");

										m_resolver.async_resolve(
											query,
											m_upstreamStrand.wrap(
												std::bind(
													&TlsCapableHttpBridge::OnResolve,
													shared_from_this(),
													std::placeholders::_1,
													std::placeholders::_2
													)
												)
											);

										return;
									}
									
									if (!closeAfter && m_request->IsPayloadComplete() == false && m_request->GetConsumeAllBeforeSending() == true)
									{
										// We need to reinitiate sequential reads of the request
										// payload until we have all of the request body, as it has
										// been marked for inspection.

										// We do this in a try/catch because getting the read buffer for the payload
										// can throw if the maximum payload size has been reached. This is defined as
										// a constexpr in BaseHttpTransaction. 
										try
										{
											auto readBuffer = m_request->GetReadBuffer();

											SetStreamTimeout(boost::posix_time::minutes(5));

											boost::asio::async_read(
												m_downstreamSocket,
												readBuffer,
												boost::asio::transfer_at_least(1),
												m_upstreamStrand.wrap(
													std::bind(
														&TlsCapableHttpBridge::OnDownstreamRead,
														shared_from_this(),
														std::placeholders::_1,
														std::placeholders::_2
													)
												)
											);

											return;
										}
										catch (std::exception& e)
										{
											ReportError(e.what());
										}
									}
									else
									{
										// Just write to the server that we're apparently already connected to. We
										// don't concern ourselves with the ShouldBlock value here on the request.
										// Once we get the upstream response headers, which gives us data about the
										// size of a yet-to-be-completed request, we will block if the value was set
										// here, but not before the http filtering engine reports this data to
										// any observer(s).

										SetStreamTimeout(boost::posix_time::minutes(5));

										auto writeBuffer = m_request->GetWriteBuffer();

										boost::asio::async_write(
											m_upstreamSocket,
											writeBuffer,
											boost::asio::transfer_all(),
											m_upstreamStrand.wrap(
												std::bind(
													&TlsCapableHttpBridge::OnUpstreamWrite,
													shared_from_this(),
													std::placeholders::_1
												)
											)
										);

										return;
									}
								}
								else
								{
									ReportError(u8"In TlsCapableHttpBridge::OnDownstreamHeaders(const boost::system::error_code&, const size_t) - Failed to read Host header from request.");
								}
							}
							else
							{
								ReportError(u8"In TlsCapableHttpBridge::OnDownstreamHeaders(const boost::system::error_code&, const size_t) - Failed to parse request.");
							}
						}

						if (error)
						{
							std::string errMsg(u8"In TlsCapableHttpBridge::OnDownstreamHeaders(const boost::system::error_code&, const size_t) - Got error:\t");
							errMsg.append(error.message());
							ReportError(errMsg);
						}

						Kill();
					}

					/// <summary>
					/// Completion handler for when an asynchronous read of the request payload from
					/// the connected client completes. Requests the request payload to be parsed
					/// and, depending on configured options, may write the data to the remote
					/// upstream server, or resize the read buffer and continue reading the request
					/// payload until completion.
					/// 
					/// In the event that this operation was a failure, meaning that the supplied
					/// error parameter was set and the code was one unexpected, the bridge will be 
					/// terminated.
					/// </summary>
					/// <param name="error">
					/// Error code that will indicate if any errors were handled during the async
					/// operation, providing details if an error did occur and was handled.
					/// </param>
					/// <param name="bytesTransferred">
					/// The number of bytes read from the connected client.
					/// </param>
					void OnDownstreamRead(const boost::system::error_code& error, const size_t bytesTransferred)
					{
						#ifndef NDEBUG
						ReportInfo(u8"TlsCapableHttpBridge::OnDownstreamRead");
						#endif // !NDEBUG

						if (m_shouldTerminate)
						{
							// The session was flagged to be killed AFTER this write completes.
							// Exit. This only happens when one end of the connection closed
							// during a read, but we got data to send to the other end before
							// this happened.
							Kill();
							return;
						}

						// EOF doesn't necessarily mean something critical happened. Could simply be
						// that we got the entire valid response, and the server closed the connection
						// after.
						if ((!error || (error == boost::asio::error::eof || (error.category() == boost::asio::error::get_ssl_category()) && (ERR_GET_REASON(error.value()) == SSL_R_SHORT_READ))))
						{
							bool closeAfter = (error == boost::asio::error::eof) || ((error.category() == boost::asio::error::get_ssl_category()) && (ERR_GET_REASON(error.value()) == SSL_R_SHORT_READ));
							bool wasSslShortRead = ((error.category() == boost::asio::error::get_ssl_category()) && (ERR_GET_REASON(error.value()) == SSL_R_SHORT_READ));

							if (closeAfter)
							{
								m_shouldTerminate = true;
							}

							if (m_request->Parse(bytesTransferred))
							{
								if (wasSslShortRead && (!m_request->IsPayloadComplete() || !m_request->HeadersComplete()))
								{
									// This is a security threat if WE TREAT THIS LIKE IT'S NORMAL.

									// If wasSslShortRead == true, but the payload is deemed complete, then
									// we simply have a dumb server that didn't do a clean TLS shutdown.
									ReportInfo(u8"In TlsCapableHttpBridge::OnDownstreamRead(const boost::system::error_code&, const size_t) - Got TLS short read and payload IS NOT complete. Aborting.");
									Kill();
									return;
								}

								if (wasSslShortRead)
								{
									ReportWarning(u8"In TlsCapableHttpBridge::OnDownstreamRead(const boost::system::error_code&, const size_t) - Got TLS short read, but payload is complete. The naughty client did not do a proper TLS shutdown.");
								}

								if (!closeAfter && m_request->IsPayloadComplete() == false && m_request->GetConsumeAllBeforeSending())
								{
									// The client has more to send and it's been flagged for inspection. Must
									// initiate a read again.

									SetStreamTimeout(boost::posix_time::minutes(5));

									try
									{
										auto readBuffer = m_request->GetReadBuffer();

										boost::asio::async_read(
											m_downstreamSocket,
											readBuffer,
											boost::asio::transfer_at_least(1),
											m_downstreamStrand.wrap(
												std::bind(
													&TlsCapableHttpBridge::OnDownstreamRead,
													shared_from_this(),
													std::placeholders::_1,
													std::placeholders::_2
													)
												)
											);

										return;
									}
									catch (std::exception& e)
									{
										std::string errMsg(u8"In TlsCapableHttpBridge::OnDownstreamRead(const boost::system::error_code&, const size_t) - Got error:\t");
										errMsg.append(e.what());
										ReportError(errMsg);
									}
								}

								SetStreamTimeout(boost::posix_time::minutes(5));

								// Just write whatever we've got to the server.
								auto writeBuffer = m_request->GetWriteBuffer();

								boost::asio::async_write(
									m_upstreamSocket, 
									writeBuffer, 
									boost::asio::transfer_all(), 
									m_upstreamStrand.wrap(
										std::bind(
											&TlsCapableHttpBridge::OnUpstreamWrite, 
											shared_from_this(), 
											std::placeholders::_1
											)
										)
									);

								return;
							}
							else
							{
								ReportError(u8"In TlsCapableHttpBridge::OnDownstreamHeaders(const boost::system::error_code&, const size_t) - Failed to parse request.");
							}
						}

						if (error)
						{
							std::string errMsg(u8"In TlsCapableHttpBridge::OnDownstreamRead(const boost::system::error_code&, const size_t) - Got error:\t");
							errMsg.append(error.message());
							ReportError(errMsg);
						}

						Kill();
					}

					/// <summary>
					/// Completion handler for when an asynchronous write of either headers or
					/// response payload data has finished being written to the connected client.
					/// 
					/// In the event that this operation was a failure, meaning that the supplied
					/// error parameter was set and the code was one unexpected, the bridge will be 
					/// terminated.
					/// </summary>
					/// <param name="error">
					/// Error code that will indicate if any errors were handled during the async
					/// operation, providing details if an error did occur and was handled.
					/// </param>
					void OnDownstreamWrite(const boost::system::error_code& error)
					{
						#ifndef NDEBUG
						ReportInfo(u8"TlsCapableHttpBridge::OnDownstreamWrite");
						#endif // !NDEBUG

						if (m_shouldTerminate)
						{
							// The session was flagged to be killed AFTER this write completes.
							// Exit. This only happens when one end of the connection closed
							// during a read, but we got data to send to the other end before
							// this happened.
							Kill();
							return;
						}

						if (m_request && m_request->GetShouldBlock() > 0)
						{
							Kill();
							return;
						}

						if (m_response && m_response->GetShouldBlock() > 0)
						{
							Kill();
							return;
						}

						// EOF doesn't necessarily mean something critical happened. Could simply be
						// that we got the entire valid response, and the server closed the connection
						// after.
						if (!error)
						{	

							if (m_response && m_response->IsPayloadComplete() == false)
							{
								// The server has more to write.

								SetStreamTimeout(boost::posix_time::minutes(5));

								try
								{
									auto readBuffer = m_response->GetReadBuffer();

									boost::asio::async_read(
										m_upstreamSocket,
										readBuffer,
										boost::asio::transfer_at_least(1),
										m_upstreamStrand.wrap(
											std::bind(
												&TlsCapableHttpBridge::OnUpstreamRead,
												shared_from_this(),
												std::placeholders::_1,
												std::placeholders::_2
												)
											)
										);

									return;
								}
								catch (std::exception& e)
								{
									std::string errMsg(u8"In TlsCapableHttpBridge::OnDownstreamWrite(const boost::system::error_code&) - Got error:\t");
									errMsg.append(e.what());
									ReportError(errMsg);
								}
							}
							else
							{							
								// We've fulfilled the request. Now, if keep-alive was specified, we'll reset and
								// start over again. Otherwise, we'll just die.
								if (m_keepAlive)
								{
									#ifndef NDEBUG
									ReportInfo(u8"In TlsCapableHttpBridge::OnDownstreamWrite(const boost::system::error_code&) - Keep-alive specified, initiating new read.");
									#endif

									// We cannot use keep-alive when we've actively blocked a
									// transaction from completing early. If we do, then the follow
									// up response from the server on the new request will be
									// polluted by the left over data from the previous, aborted
									// (blocked) request. Therefore, we have no choice but to
									// entirely terminate the bridge and force the client to open a
									// new connection.

									if ((m_request && m_request->GetShouldBlock() != 0) || (m_response && m_response->GetShouldBlock() != 0))
									{
										Kill();
										return;
									}

									SetStreamTimeout(boost::posix_time::minutes(5));

									try
									{
										m_request.reset(new http::HttpRequest());
										m_response.reset(new http::HttpResponse());
									}
									catch (std::exception& e)
									{
										ReportError(e.what());
										Kill();
										return;
									}

									m_shouldTerminate = false;

									// XXX TODO - This is ugly, our bad design is showing. See notes in the
									// EventReporter class header.
									m_request->SetOnInfo(m_onInfo);
									m_request->SetOnWarning(m_onWarning);
									m_request->SetOnError(m_onError);
									m_response->SetOnInfo(m_onInfo);
									m_response->SetOnWarning(m_onWarning);
									m_response->SetOnError(m_onError);

									TryInitiateHttpTransaction();
									return;
								}
							}							
						}
						else
						{
							std::string errMsg(u8"In TlsCapableHttpBridge::OnDownstreamWrite(const boost::system::error_code&) - Got error:\t");
							errMsg.append(error.message());
							ReportError(errMsg);
						}

						Kill();
					}

					/// <summary>
					/// Completion handler for when the asynchrous wait operation on the stream
					/// timer is finished, meaning that the timeout period has been reached, or that
					/// the operation was cancelled. If the timeout has been reached, then the
					/// bridge should be terminated. If the operation was aborted, then the function
					/// will return without calling for a termination of the bridge.
					/// 
					/// In the event that this operation was a failure, meaning that the supplied
					/// error parameter was set and the code was one unexpected, the bridge will be 
					/// terminated.
					/// </summary>
					/// <param name="error">
					/// Error code that will indicate if any errors were handled during the async
					/// operation, providing details if an error did occur and was handled.
					/// </param>
					void OnStreamTimeout(const boost::system::error_code& error)
					{

						#ifndef NDEBUG
							ReportInfo(u8"TlsCapableHttpBridge<network::TlsSocket>::OnStreamTimeout");
						#endif // !NDEBUG

						if (error)
						{
							if (error == boost::asio::error::operation_aborted)
							{
								// Aborts are normal, as pending async_waits are cancelled every time that
								// the timeout is reset. Therefore, we safely ignore them.
								return;
							}
							else
							{
								// XXX TODO - Perhaps in the event of an error, we should return and avoid
								// calling ::Kill()?
								std::string errMessage(u8"In TlsCapableHttpBridge<BridgeSocketType>::OnStreamTimeout(const boost::system::error_code&) - Got error:\t");
								errMessage.append(error.message());
								ReportError(errMessage);
							}
						}

						Kill();
					}					

					/// <summary>
					/// Completion handler for when the asynchrous handshake operation with the
					/// remote upstream host has finished. If the operation was a success, then a
					/// context by which to serve the connected client will either be retrieved, or
					/// created, stored and then retrieved.
					/// 
					/// In the event that this operation was a failure, meaning that the supplied
					/// error parameter was set and the code was one unexpected, the bridge will be 
					/// terminated.
					/// </summary>
					/// <param name="error">
					/// Error code that will indicate if any errors were handled during the async
					/// operation, providing details if an error did occur and was handled.
					/// </param>
					void OnUpstreamHandshake(const boost::system::error_code& error)
					{

						#ifndef NDEBUG
						ReportInfo(u8"TlsCapableHttpBridge<network::TlsSocket>::OnUpstreamHandshake");
						#endif // !NDEBUG

						if (!error && m_upstreamCert != nullptr)
						{
							boost::asio::ssl::context* serverCtx = nullptr;

							try
							{
								serverCtx = m_certStore->GetServerContext(m_upstreamHost, m_upstreamCert);
							}
							catch (std::exception& e)
							{
								serverCtx = nullptr;
								std::string errMessage(u8"In TlsCapableHttpBridge<network::TlsSocket>::OnUpstreamHandshake(const boost::system::error_code&) - Got error:\t");
								errMessage.append(e.what());
								ReportError(errMessage);
							}

							if (serverCtx != nullptr)
							{
								if (SSL_set_SSL_CTX(m_downstreamSocket.native_handle(), serverCtx->native_handle()) == serverCtx->native_handle())
								{
									// Set timeouts
									SetStreamTimeout(boost::posix_time::minutes(5));
									//
									
									m_downstreamSocket.async_handshake(
										network::TlsSocket::server, 
										m_downstreamStrand.wrap(
											std::bind(
												&TlsCapableHttpBridge::OnDownstreamHandshake, 
												shared_from_this(), 
												std::placeholders::_1
												)
											)
										);

									return;
								}
								else
								{
									ReportError(u8"In TlsCapableHttpBridge<network::TlsSocket>::OnUpstreamHandshake(const boost::system::error_code&) - Failed to correctly set context.");
								}
							}
							else
							{
								ReportError(u8"In TlsCapableHttpBridge<network::TlsSocket>::OnUpstreamHandshake(const boost::system::error_code&) - Failed to fetch spoofed context.");
							}
						}
						else
						{
							if (error)
							{
								std::string errMsg(u8"In TlsCapableHttpBridge<network::TlsSocket>::OnUpstreamHandshake(const boost::system::error_code&) - Got error:\t");
								errMsg.append(error.message());
								ReportError(errMsg);
							}

							if (m_upstreamCert == nullptr)
							{
								ReportError(u8"In TlsCapableHttpBridge<network::TlsSocket>::OnUpstreamHandshake(const boost::system::error_code&) - Upstream cert is nullptr!");
							}
						}

						Kill();
					}

					/// <summary>
					/// Completion handler for when the asynchrous handshake operation with the
					/// connected client has finished. If the operation was a success, then the
					/// process of reading the client's request headers will begin.
					/// 
					/// In the event that this operation was a failure, meaning that the supplied
					/// error parameter was set and the code was one unexpected, the bridge will be 
					/// terminated.
					/// </summary>
					/// <param name="error">
					/// Error code that will indicate if any errors were handled during the async
					/// operation, providing details if an error did occur and was handled.
					/// </param>
					void OnDownstreamHandshake(const boost::system::error_code& error)
					{

						#ifndef NDEBUG
						ReportInfo(u8"TlsCapableHttpBridge<network::TlsSocket>::OnDownstreamHandshake");
						#endif // !NDEBUG

						if (!error)
						{
							SetNoDelay(UpstreamSocket(), true);
							SetNoDelay(DownstreamSocket(), true);

							TryInitiateHttpTransaction();
							return;
						}

						std::string errMessage(u8"In TlsCapableHttpBridge<network::TlsSocket>::OnUpstreamHandshake(const boost::system::error_code&) - Got error:\t");
						errMessage.append(error.message());
						ReportError(errMessage);

						Kill();
					}
	
					/// <summary>
					/// Handler for the peek read operation on newly connected TLS clients. Only
					/// ever used in the case that BridgeSocketType is network::TlsSocket. In this
					/// handler, we manually parse the TLS client hello message, search for the SNI
					/// extension and attempt to extract the value. If we succeed, then the
					/// extracted host will be resolved with "https" as the service, so that we get
					/// endpoints already configured to connect to port 443. The OnResolve handlers
					/// are specialized, so the correct functionality and order of operations will
					/// be initiated once the resolver handler is invoked depending for TLS or
					/// non-TLS clients. For TLS clients, handshakes and upstream server certificate
					/// verification will occur when the resolver returns valid enpoints.
					/// 
					/// In the event that this operation was a failure, meaning that the supplied
					/// error parameter was set and the code was one unexpected, the bridge will be 
					/// terminated.
					/// </summary>
					/// <param name="error">
					/// Error code that will indicate if any errors were handled during the async
					/// operation, providing details if an error did occur and was handled.
					/// </param>
					/// <param name="bytesTransferred">
					/// The amount of bytes read during the async peek read operation. This is how
					/// many valid bytes were written to the m_tlsPeekBuffer member array.
					/// </param>
					void OnTlsPeek(const boost::system::error_code& error, const size_t bytesTransferred)
					{
					
						#ifndef NDEBUG
						ReportInfo(u8"TlsCapableHttpBridge<network::TlsSocket>::OnTlsPeek");
						#endif // !NDEBUG

						// Parsing Numbers
						//
						// https://www.ietf.org/rfc/rfc5246.txt Sections 4.1, 4.4:
						// Data is stored is big-endian. Basic storage unit is uint8_t (one byte, 8 bits). Multibyte data sequences are
						// concatenated left to right. Example code given is:
						// value = (byte[0] << 8*(n-1)) | (byte[1] << 8*(n-2)) ... | byte[n - 1];
						//
						//
						// Parsing Strings
						//
						// https://www.ietf.org/rfc/rfc4366.txt Section 3.1, page 9:
						// "The hostname is represented as a byte string using UTF - 8 encoding[UTF8], without a trailing dot."
						// If hostname only contains US-ASCII chars, labels must be separated using 0x2E byte, representing
						// the U+002E char.

						if (m_tlsPeekBuffer != nullptr && !error && bytesTransferred > 0)
						{						
							if (bytesTransferred > MinTlsHelloLength)
							{
								auto sharedThis = shared_from_this();
								auto WithinBounds = [sharedThis, this]
									(const std::unique_ptr< std::array<char, TlsPeekBufferSize> >& arr, const size_t position, const size_t validDataLength, int crumb = 0)->bool
								{
									// Crumb param helps identify which point the check was done and failed. Not really
									// sure if I should take this out after I finish sorting this parsing method, as it
									// may assist in the future.
									if (position >= arr->size() || position > validDataLength)
									{
										#ifndef NDEBUG
											std::string errMessage(u8"In TlsCapableHttpBridge<network::TlsSocket>::OnTlsPeek(const boost::system::error_code&, const size_t) - ");
											errMessage.append(u8"Index in buffer is out of bounds at position ").append(std::to_string(position)).append(u8".\n\n");
											errMessage.append(u8"Went out of bounds at check ").append(std::to_string(crumb)).append(u8".");
											ReportError(errMessage);
										#endif
										
										return false;
									}

									return true;
								};

								auto contentType = (*m_tlsPeekBuffer)[0];
								auto versionMajor = (*m_tlsPeekBuffer)[1];
								auto versionMinor = (*m_tlsPeekBuffer)[2];
								auto handshakeType = (*m_tlsPeekBuffer)[5];

								if ((versionMajor == 3 && versionMinor > 0) || (versionMinor > 3))
								{
									if (contentType == 22 && handshakeType == 1)
									{
										boost::string_ref hostName(m_tlsPeekBuffer->data(), bytesTransferred);
										size_t hostnameLength = 0;

										size_t position = MinTlsHelloLength;

										// Get session ID length.
										size_t sessionIdLength = reinterpret_cast<const char&>((*m_tlsPeekBuffer)[position]);

										// Now skip past session ID.
										position += sessionIdLength + 1;

										if (!WithinBounds(m_tlsPeekBuffer, position + 1, bytesTransferred))
										{
											Kill();
											return;
										}

										// Get cipher suites length.
										size_t cipherSuitesLength = ((reinterpret_cast<const char&>((*m_tlsPeekBuffer)[position])) << 8) | reinterpret_cast<const char&>((*m_tlsPeekBuffer)[position + 1]);

										// Now skip past cipher suites.
										position += cipherSuitesLength + 2;

										if (!WithinBounds(m_tlsPeekBuffer, position, bytesTransferred, 1))
										{
											Kill();
											return;
										}

										// Get compression methods length.
										size_t compressionMethodsLength = reinterpret_cast<const char&>((*m_tlsPeekBuffer)[position]);

										// Now skip past compression methods.
										position += compressionMethodsLength + 1;

										if (!WithinBounds(m_tlsPeekBuffer, position + 1, bytesTransferred, 2))
										{
											Kill();
											return;
										}

										// Get extensions length.
										size_t extensionsLength = ((reinterpret_cast<const char&>((*m_tlsPeekBuffer)[position])) << 8) | reinterpret_cast<const char&>((*m_tlsPeekBuffer)[position + 1]);

										// Now skip past just the extensions length bytes.
										position += 2;

										if (!WithinBounds(m_tlsPeekBuffer, position, bytesTransferred, 3))
										{
											Kill();
											return;
										}

										// Parse each extension till we hopefully find SNI
										bool notDone = true;
										while (position < bytesTransferred && notDone)
										{
											if (!WithinBounds(m_tlsPeekBuffer, position + 4, bytesTransferred, 4))
											{
												Kill();
												return;
											}

											// Get the extension type.
											size_t extensionType = ((reinterpret_cast<const char&>((*m_tlsPeekBuffer)[position])) << 8) | reinterpret_cast<const char&>((*m_tlsPeekBuffer)[position + 1]);

											// Get the length of this extension.
											size_t extensionLength = ((reinterpret_cast<const char&>((*m_tlsPeekBuffer)[position + 2])) << 8) | reinterpret_cast<const char&>((*m_tlsPeekBuffer)[position + 3]);
												
											// Skip beyond extension type and extension length.
											position += 4;

											// Check if it's SNI
											if (extensionType == 0)
											{
												// Skip Server Name Indication Length.
												position += 2;

												if (!WithinBounds(m_tlsPeekBuffer, position + 4, bytesTransferred, 5))
												{
													Kill();
													return;
												}

												while (position < bytesTransferred && notDone)
												{
													if (!WithinBounds(m_tlsPeekBuffer, position + 3, bytesTransferred, 6))
													{
														Kill();
														return;
													}

													// Get SNI part length.
													size_t sniPartLength = ((reinterpret_cast<const char&>((*m_tlsPeekBuffer)[position + 1])) << 8) | reinterpret_cast<const char&>((*m_tlsPeekBuffer)[position + 2]);
																									
													if ((*m_tlsPeekBuffer)[position] == 0)
													{
														hostnameLength = sniPartLength;
														hostName = hostName.substr(position + 3, sniPartLength);
														notDone = false;
														break;
													}

													position += 3 + sniPartLength;
												}
											}

											position += extensionLength;
										}

										if (hostnameLength > 0)
										{
											m_upstreamHost = hostName.to_string();

											// XXX TODO - See notes in the version of ::OnResolve(...), specialized for TLS clients.
											m_upstreamHostPort = 443;

											try
											{
												boost::asio::ip::tcp::resolver::query query(m_upstreamHost, "https");
												m_resolver.async_resolve(
													query, 
													m_upstreamStrand.wrap(
														std::bind(
															&TlsCapableHttpBridge::OnResolve, 
															shared_from_this(), 
															std::placeholders::_1, 
															std::placeholders::_2
															)
														)
													);

												return;
											}
											catch (std::exception& e)
											{
												std::string errorMessage(u8"In TlsCapableHttpBridge<network::TlsSocket>::OnTlsPeek(const boost::system::error_code&, const size_t) - Got Error:\t");
												errorMessage.append(e.what());
												ReportError(errorMessage);
											}
										}
										else
										{
											ReportError(u8"In TlsCapableHttpBridge<network::TlsSocket>::OnTlsPeek(const boost::system::error_code&, const size_t) - Failed to extract hostname from SNI extension.");
										}
									}
									else
									{
										ReportWarning(u8"In TlsCapableHttpBridge<network::TlsSocket>::OnTlsPeek(const boost::system::error_code&, const size_t) - Not a TLS client hello.");
									}
								}
								else
								{
									ReportWarning(u8"In TlsCapableHttpBridge<network::TlsSocket>::OnTlsPeek(const boost::system::error_code&, const size_t) - Not a TLS client.");
								}
							}
						}
						else
						{							
							if (error)
							{
								std::string errorMessage(u8"In TlsCapableHttpBridge<network::TlsSocket>::OnTlsPeek(const boost::system::error_code&, const size_t) - Got Error:\t");
								errorMessage.append(error.message());
								ReportError(errorMessage);
							}
							else if(!m_tlsPeekBuffer)
							{
								ReportError(u8"In TlsCapableHttpBridge<network::TlsSocket>::OnTlsPeek(const boost::system::error_code&, const size_t) - TLS peek buffer is nullptr!");
							}
						}

						Kill();
					}

					/// <summary>
					/// Callback supplied for the handshake process with the remote upstream server.
					/// This is the client verifying the validity of the server's certificate. This
					/// callback performs certificate verification according to RFC 2818, which is
					/// little more than verifying the subject information of the certificate. This
					/// is not the only verification that takes place. The upstream socket, which
					/// acts on behalf of the client, is configured with a default client context
					/// which has been configured with the cURL/Mozilla ca-bundle to use for
					/// verification. This callback serves as an additional layer of verification,
					/// and our only real purpose of implementing it at all is to scoop up a pointer
					/// to the remote certificate for the purpose of spoofing it later on.
					/// 
					/// In the event that the remote upstream server's certificate passes
					/// verification, it will be stored for subsuquent methods to supply to the in
					/// memory certificate store, if no context for the remote host's hostname yet exists.
					/// </summary>
					/// <param name="preverified">
					/// A bool which indicates if the current peer certificate and other context
					/// data has pass pre-verification.
					/// </param>
					/// <param name="ctx">
					/// The context containing data about the remote peer, such as the certificate
					/// being verified.
					/// </param>
					/// <returns>
					/// True if the certificate has been verified, false otherwise.
					/// </returns>
					bool VerifyServerCertificateCallback(bool preverified, boost::asio::ssl::verify_context& ctx)
					{

						#ifndef NDEBUG
						ReportInfo(u8"TlsCapableHttpBridge<network::TlsSocket>::VerifyServerCertificateCallback");
						#endif // !NDEBUG

						boost::asio::ssl::rfc2818_verification v(m_upstreamHost);

						bool verified = v(preverified, ctx);

						// Keep a ptr to the most recently verified cert in the chain. The last time
						// this is set, it should be the cert we want to spoof.
						X509* curCert = X509_STORE_CTX_get_current_cert(ctx.native_handle());

						if (verified)
						{
							m_upstreamCert = curCert;
						}
						else
						{
							if (curCert != nullptr)
							{
								char subjectName[MaxDomainNameSize];
								X509_NAME_oneline(X509_get_subject_name(curCert), subjectName, MaxDomainNameSize);
								
								std::string verifyFailedErrorMessage("In TlsCapableHttpBridge<network::TlsSocket>::VerifyServerCertificateCallback(bool, boost::asio::ssl::verify_context&) - Cert for ");																
								verifyFailedErrorMessage.append(subjectName);
								verifyFailedErrorMessage.append(u8" failed verification.");
								
								ReportError(verifyFailedErrorMessage);
							}
							else
							{
								std::string verifyFailedErrorMessage("In TlsCapableHttpBridge<network::TlsSocket>::VerifyServerCertificateCallback(bool, boost::asio::ssl::verify_context&) - Certificate is null.");
								ReportError(verifyFailedErrorMessage);
							}

							m_upstreamCert = nullptr;
						}

						return verified;
					}

					void HandleDownstreamPassthrough(std::shared_ptr<std::array<char, 1638400>> buff, const boost::system::error_code& ec, const size_t bytesTransferred)
					{
						//ReportInfo(u8"HandleDownstreamPassthrough");

						if ((!ec || (ec == boost::asio::error::eof || (ec.category() == boost::asio::error::get_ssl_category()) && (ERR_GET_REASON(ec.value()) == SSL_R_SHORT_READ))))
						{
							SetStreamTimeout(boost::posix_time::minutes(5));

							bool closeAfter = (ec == boost::asio::error::eof) || ((ec.category() == boost::asio::error::get_ssl_category()) && (ERR_GET_REASON(ec.value()) == SSL_R_SHORT_READ));

							if (bytesTransferred > 0)
							{
								auto self(shared_from_this());

								boost::asio::async_write(
									m_upstreamSocket,
									boost::asio::buffer(buff->data(), bytesTransferred),
									boost::asio::transfer_exactly(bytesTransferred),
									m_upstreamStrand.wrap(
										[this, self, buff, closeAfter](const boost::system::error_code& err, const size_t bytesSent)
										{
											if (closeAfter)
											{
												ReportInfo(u8"In TlsCapableHttpBridge::HandleDownstreamPassthrough(const boost::system::error_code&) - Connection closed by upstream.");
												Kill();
												return;
											}

											if (!err)
											{
												boost::asio::async_read(
													m_downstreamSocket,
													boost::asio::buffer(buff->data(), buff->size()),
													boost::asio::transfer_at_least(1),
													std::bind(
														&TlsCapableHttpBridge::HandleDownstreamPassthrough,
														shared_from_this(),
														buff,
														std::placeholders::_1,
														std::placeholders::_2
													)
												);
											}
										}
									)
								);

								return;
							}

							if (closeAfter)
							{
								ReportInfo(u8"In TlsCapableHttpBridge::HandleDownstreamPassthrough(const boost::system::error_code&) - Connection closed by upstream.");
								Kill();
								return;
							}

							boost::asio::async_read(
								m_downstreamSocket,
								boost::asio::buffer(buff->data(), buff->size()),
								boost::asio::transfer_at_least(1),
								std::bind(
									&TlsCapableHttpBridge::HandleDownstreamPassthrough,
									shared_from_this(),
									buff,
									std::placeholders::_1,
									std::placeholders::_2
								)
							);

							return;
						}
						else
						{
							if (ec)
							{
								//std::string errMsg(u8"In TlsCapableHttpBridge::HandleDownstreamPassthrough(const boost::system::error_code&) - Got error in handler:\t");
								//errMsg.append(ec.message());
								//ReportError(errMsg);
							}
						}

						// Let the dealine timer kill us. Just in case the other end of the passthrough
						// is still working at something.
						Kill();
					}

					void HandleUpstreamPassthrough(std::shared_ptr<std::array<char, 1638400>> buff, const boost::system::error_code& ec, const size_t bytesTransferred)
					{
						//ReportInfo(u8"HandleUpstreamPassthrough");

						if ((!ec || (ec == boost::asio::error::eof || (ec.category() == boost::asio::error::get_ssl_category()) && (ERR_GET_REASON(ec.value()) == SSL_R_SHORT_READ))))
						{
							SetStreamTimeout(boost::posix_time::minutes(5));

							bool closeAfter = (ec == boost::asio::error::eof) || ((ec.category() == boost::asio::error::get_ssl_category()) && (ERR_GET_REASON(ec.value()) == SSL_R_SHORT_READ));

							if (bytesTransferred > 0)
							{
								auto self(shared_from_this());

								boost::asio::async_write(
									m_downstreamSocket,
									boost::asio::buffer(buff->data(), bytesTransferred),
									boost::asio::transfer_exactly(bytesTransferred),
									m_downstreamStrand.wrap(
										[this, self, buff, closeAfter](const boost::system::error_code& err, const size_t bytesSent)
										{
											if (closeAfter)
											{
												ReportInfo(u8"In TlsCapableHttpBridge::HandleUpstreamPassthrough(const boost::system::error_code&) - Connection closed by downstream.");
												Kill();
												return;
											}

											if (!err)
											{
												boost::asio::async_read(
													m_upstreamSocket,
													boost::asio::buffer(buff->data(), buff->size()),
													boost::asio::transfer_at_least(1),
													std::bind(
														&TlsCapableHttpBridge::HandleUpstreamPassthrough,
														shared_from_this(),
														buff,
														std::placeholders::_1,
														std::placeholders::_2
													)
												);
											}
										}
									)
								);

								return;
							}

							if (closeAfter)
							{
								ReportInfo(u8"In TlsCapableHttpBridge::HandleUpstreamPassthrough(const boost::system::error_code&) - Connection closed by downstream.");
								Kill();
								return;
							}

							boost::asio::async_read(
								m_upstreamSocket,
								boost::asio::buffer(buff->data(), buff->size()),
								boost::asio::transfer_at_least(1),
								std::bind(
									&TlsCapableHttpBridge::HandleUpstreamPassthrough,
									shared_from_this(),
									buff,
									std::placeholders::_1,
									std::placeholders::_2
								)
							);

							return;
						}
						else
						{
							if (ec)
							{
								//std::string errMsg(u8"In TlsCapableHttpBridge::HandleUpstreamPassthrough(const boost::system::error_code&) - Got error in handler:\t");
								//errMsg.append(ec.message());
								//ReportError(errMsg);
							}
						}

						// Let the dealine timer kill us. Just in case the other end of the passthrough
						// is still working at something.
						Kill();
					}

					void StartPassthroughVolley(std::shared_ptr<std::array<char, TlsPeekBufferSize>> downstreamBuff, const size_t initialBytes)
					{	
						ReportInfo(u8"Starting passthrough.");
						SetStreamTimeout(boost::posix_time::minutes(5));

						boost::system::error_code err;
						err.clear();

						boost::system::error_code iwe;
						iwe.clear();

						try
						{
							boost::asio::write(m_upstreamSocket, boost::asio::buffer(downstreamBuff->data(), initialBytes), boost::asio::transfer_exactly(initialBytes), iwe);
						}
						catch (std::exception& e)
						{
							std::string errMsg(u8"In TlsCapableHttpBridge::StartPassthroughVolley(std::shared_ptr<std::array<char, TlsPeekBufferSize>>, const size_t) - Got error while writing initial payload:\t");
							errMsg.append(e.what());
							ReportError(errMsg);
						}

						if (iwe)
						{
							std::string errMsg(u8"In TlsCapableHttpBridge::StartPassthroughVolley(std::shared_ptr<std::array<char, TlsPeekBufferSize>>, const size_t) - Got error while writing initial payload:\t");
							errMsg.append(iwe.message());
							ReportError(errMsg);
						}

						try
						{
							std::shared_ptr<std::array<char, 1638400>> dsb = std::make_shared< std::array<char, 1638400> >();
							std::shared_ptr<std::array<char, 1638400>> usb = std::make_shared< std::array<char, 1638400> >();

							HandleDownstreamPassthrough(dsb, err, 0);
							HandleUpstreamPassthrough(usb, err, 0);

						}
						catch (std::exception& e)
						{
							std::string errMsg(u8"In TlsCapableHttpBridge::StartPassthroughVolley(std::shared_ptr<std::array<char, TlsPeekBufferSize>>, const size_t) - Got errorsss while writing initial payload:\t");
							errMsg.append(e.what());
							ReportError(errMsg);
						}
					}

					/// <summary>
					/// Attempts to start the HTTP transaction process by doing a peek read from the
					/// downstream (client) socket, to determine if the incoming data is legal HTTP
					/// data. If this is the case, then this function will initiate the asynchronous
					/// operation to read all headers from the downstream socket.
					///
					/// If it is determined that the incoming data is not HTTP data, but is Websocket
					/// data, then the process will start a back and forth volley with a raw buffer
					/// between the upstream and downstream sockets, passing the data through
					/// directly without processing or parsing it.
					/// </summary>
					void TryInitiateHttpTransaction()
					{
						try
						{
							// Allow 5 seconds for a peek read.
							SetStreamTimeout(boost::posix_time::minutes(5));

							std::shared_ptr<std::array<char, TlsPeekBufferSize>> httpPeekBuffer = std::make_shared< std::array<char, TlsPeekBufferSize> >();

							boost::asio::async_read(
								m_downstreamSocket,
								boost::asio::buffer(httpPeekBuffer->data(), httpPeekBuffer->size()),
								boost::asio::transfer_at_least(18),
								m_downstreamStrand.wrap(
									std::bind(
										&TlsCapableHttpBridge::OnInitialPeek,
										shared_from_this(),
										std::placeholders::_1,
										std::placeholders::_2,
										httpPeekBuffer)
								)
							);
						}
						catch (std::exception& e)
						{
							std::string err(e.what());
							ReportError(err);
						}
					}
					

					void OnInitialPeek(const boost::system::error_code& error, const size_t bytesTransferred, std::shared_ptr<std::array<char, TlsPeekBufferSize>> httpPeekBuffer)
					{
						if (!error && httpPeekBuffer && httpPeekBuffer.get() && httpPeekBuffer->data() && bytesTransferred > 0)
						{
							
							// Cancel the stream timeout mechanism before entering starting this process. We're going to need
							// to possibly leave this cancelled if we're handling a passthrough connection.
							SetStreamTimeout(boost::posix_time::minutes(5));
							
							PreviewParser p;
							std::string parsedHost;
							auto parseResult = p.Parse(httpPeekBuffer->data(), bytesTransferred, parsedHost);

							switch (parseResult)
							{
								case PreviewParser::ParseResult::Failure:
								{
									ReportError(u8"In TlsCapableHttpBridge:: InitiateHttpTransaction() - Failed when trying to peek connected client.");
									Kill();
									return;
								}
								break;

								case PreviewParser::ParseResult::IsHttp:
								{	
									// Just go ahead and start officially reading the headers.

									// Set the timeout to something reasonable.
									SetStreamTimeout(boost::posix_time::minutes(5));

									// Create a new request for this data and just jump to OnDownstreamHeaders.
									try
									{
										m_request.reset(new http::HttpRequest(httpPeekBuffer->data(), bytesTransferred));
										m_shouldTerminate = false;
									}
									catch (std::exception& e)
									{
										ReportError(e.what());
										Kill();
										return;
									}

									OnDownstreamHeaders(error, bytesTransferred);
									return;									
								}
								break;

								case PreviewParser::ParseResult::HttpWithUpgrade:
								{
									ReportInfo(u8"HTTP with upgrade.");

									// If it's non-TLS, then we need to resolve the host and connect to it
									// as well. If it is TLS, then we don't care because this is done
									// right away on connect with TLS clients because the host is extracted
									// from SNI extension.
									bool needsResolveAndConnect = std::is_same<BridgeSocketType, network::TcpSocket>::value;

									if (needsResolveAndConnect)
									{
										
										SetStreamTimeout(boost::posix_time::minutes(5));

										if (parsedHost.size() == 0)
										{
											ReportWarning(u8"HTTP-With-Upgrade passthrough detected, but no host extracted.");
											Kill();
											return;
										}

										// Trim port, if present.
										auto portPos = parsedHost.find_last_of(u8":");

										// Find out if a custom port is being used and pass it
										// to our resolve handler so we can adjust where we're
										// connecting to on resolve.
										size_t customPort = 0;

										if (portPos != std::string::npos)
										{
											
											parsedHost = parsedHost.substr(0, portPos);

											if (portPos + 1 < parsedHost.size())
											{
												
												try
												{
													customPort = static_cast<uint16_t>(std::stoi(parsedHost.substr(portPos + 1)));
												}
												catch (...)
												{
													
													customPort = 0;
												}
											}
										}

										/*
										if (m_filteringEngine->ShouldBlockHost(parsedHost))
										{
											// This host is filtered.
											Kill();
											return;
										}
										*/

										boost::asio::ip::tcp::resolver::query query(parsedHost, std::is_same<BridgeSocketType, network::TlsSocket>::value ? "https" : "http");

										auto self(shared_from_this());

										m_resolver.async_resolve(
											query,
											m_upstreamStrand.wrap(											
												[this, self, customPort, httpPeekBuffer, bytesTransferred](const boost::system::error_code& error, boost::asio::ip::tcp::resolver::iterator endpointIterator)
												{
													if (!error)
													{
														auto ep = *endpointIterator;

														if (customPort != 0)
														{
															// A custom port was parsed from the peeked request headers.
								
															ep.endpoint().port(customPort);
														}

														UpstreamSocket().async_connect(
															ep,
															m_upstreamStrand.wrap(
																[this, self, httpPeekBuffer, bytesTransferred](const boost::system::error_code& error)
																{
																	if (!error)
																	{
																		// We managed to connect, do just start to volley.
																		StartPassthroughVolley(httpPeekBuffer, bytesTransferred);
																		return;
																	}

																	// Failed to connect.
																	ReportInfo(u8"Failed to connect");
																	Kill();
																}
															)
														);

														return;
													}

						
													// Failed to resolve host.
													ReportInfo(u8"Failed to resolve");
													Kill();
												}
											)
										);										

										return;
									}
									else
									{
										// Check here if already-established host is blocked. In this case, the host would have been
										// extracted via SNI extension parsing.
										if (m_upstreamHost.size() > 0)
										{
											/*
											if (m_filteringEngine->ShouldBlockHost(m_upstreamHost))
											{
												// This host is filtered.
												Kill();
												return;
											}
											*/
										}

										// We're already connected as HTTPS so just do the volley.
										StartPassthroughVolley(httpPeekBuffer, bytesTransferred);
										return;
									}
								}
								break;

								case PreviewParser::ParseResult::NotHttp:
								{	
									// If this is not HTTP AND it's not TLS with SNI, then we can't do anything about this.
									if (std::is_same<BridgeSocketType, network::TcpSocket>::value)
									{
										
										ReportError(u8"In TlsCapableHttpBridge::TryInitiateHttpTransaction() - Connected client is non-tls and sending content in an unexpected protocol. Terminating because no mechanism exists to resolve the original upstream host.");
										Kill();
										return;
									}
									else
									{
										ReportInfo(u8"Not http and is TLS.");

										// Check here if already-established host is blocked. In this case, the host would have been
										// extracted via SNI extension parsing.
										if (m_upstreamHost.size() > 0)
										{
											/*
											if (m_filteringEngine->ShouldBlockHost(m_upstreamHost))
											{
												// This host is filtered.
												Kill();
												return;
											}
											*/
										}

										// We're already connected as HTTPS so just do the volley.
										StartPassthroughVolley(httpPeekBuffer, bytesTransferred);
										return;
									}
								}
								break;
							}
						}

						
						//ReportInfo(u8"Deder");
						//Kill();
					}								

					/// <summary>
					/// Sets the duration from now when the stream timer should expire.
					/// </summary>
					/// <param name="expiry">
					/// The boost::posix_time::time_duration when the expiry should occur from now.
					/// </param>
					void SetStreamTimeout(const boost::posix_time::time_duration& expiry)
					{
						m_streamTimer.cancel();

						m_streamTimer.expires_from_now(expiry);

						m_streamTimer.async_wait(std::bind(&TlsCapableHttpBridge::OnStreamTimeout, shared_from_this(), std::placeholders::_1));
					}

					/// <summary>
					/// Cancels the current stream timer and then sets it to positive infinity.
					/// </summary>
					void SetInfiniteStreamTimeout()
					{
						m_streamTimer.cancel();

						m_streamTimer.expires_at(boost::posix_time::pos_infin);
						return;
					}

					/// <summary>
					/// Sets the linger option to the specified values for the supplied socket.
					/// </summary>
					/// <param name="socket">
					/// The socket to configure.
					/// </param>
					/// <param name="enabled">
					/// The value indicating whether the property should be enabled or disabled.
					/// </param>
					/// <param name="value">
					/// The linger timeout, in the event that the property is enabled.
					/// </param>
					void SetLinger(boost::asio::ip::tcp::socket& socket, const bool enabled, const int value)
					{
						boost::system::error_code err;

						socket.lowest_layer().set_option(boost::asio::socket_base::linger(enabled, value), err);

						if (err)
						{
							std::string errorMessage(u8"In TlsCapableHttpBridge<BridgeSocketType>::SetLinger(boost::asio::ip::tcp::socket&, const bool) - While setting linger state, got error:\t");
							errorMessage.append(err.message());
							ReportError(errorMessage);
						}
					}

					/// <summary>
					/// Enables or disables the TCP Nagle algorithm for the supplied socket.
					/// </summary>
					/// <param name="socket">
					/// The socket to configure.
					/// </param>
					/// <param name="value">
					/// The value indicating whether the property should be enabled or disabled.
					/// </param>
					void SetNoDelay(boost::asio::ip::tcp::socket& socket, const bool value)
					{
						boost::system::error_code err;
						
						socket.lowest_layer().set_option(boost::asio::ip::tcp::no_delay(value), err);

						if (err)
						{
							std::string errorMessage(u8"In TlsCapableHttpBridge<BridgeSocketType>::SetNoDelay(boost::asio::ip::tcp::socket&, const bool) - While setting Nagle algorithm enabled state, got error:\t");
							errorMessage.append(err.message());
							ReportError(errorMessage);
						}
					}

					/// <summary>
					/// Determines if the supplied socket has data waiting to be read off the buffer.
					/// This is used to attempt to determine if a transaction is complete whenever we
					/// have to handle a passthrough connection.
					/// </summary>
					/// <param name="socket">
					/// The socket to be polled.
					/// </param>
					/// <returns>
					/// True of the supplied socket has data to be read, false otherwise.
					/// </returns>
					const bool SocketHasData(boost::asio::ip::tcp::socket& socket)
					{
						boost::asio::socket_base::bytes_readable command(true);
						socket.io_control(command);
						std::size_t bytes_readable = command.get();

						return bytes_readable > 0;
					}

					const bool ShouldBlockTransaction(http::BaseHttpTransaction* request, http::BaseHttpTransaction* response = nullptr)
					{
						auto requestHeaders = request->HeadersToString();
						auto responseHeaders = response != nullptr ? response->HeadersToString() : std::string();
						
						const char* requestPayload = nullptr;
						uint32_t requestPayloadSize = 0;

						const char* responsePayload = nullptr;
						uint32_t responsePayloadSize = 0;


						uint32_t nextAction = 0;
						char* customBlockResponse = nullptr;
						bool shouldBlock = false;
						uint32_t customBlockResponseLen = 0;

						bool inspectRequest = request->GetConsumeAllBeforeSending() && request->IsPayloadComplete();
						bool inspectResponse = (response != nullptr && response->GetConsumeAllBeforeSending() && response->IsPayloadComplete());

						if ((inspectRequest && !inspectResponse) || (inspectRequest && inspectResponse))
						{
							requestPayload = inspectRequest ? request->GetPayload().data() : nullptr;
							requestPayloadSize = inspectRequest ? request->GetPayload().size() : 0;

							responsePayload = inspectResponse ? response->GetPayload().data() : nullptr;
							responsePayloadSize = inspectResponse ? response->GetPayload().size() : 0;

							m_onMessageEnd(
								requestHeaders.c_str(), requestHeaders.size(),
								requestPayload, requestPayloadSize,
								responseHeaders.c_str(), responseHeaders.size(),
								responsePayload, responsePayloadSize,
								&shouldBlock, &customBlockResponse, &customBlockResponseLen);

							if (shouldBlock)
							{
								if (customBlockResponse != nullptr)
								{	
									std::vector<char> customPayloadVec(customBlockResponse, customBlockResponse + customBlockResponseLen);
									delete[] customBlockResponse;									
									request->SetPayload(customPayloadVec, true);
									return true;
								}
								else
								{	
									request->Make204();
								}

								request->SetShouldBlock(1);
								
								return true;
							}
						}
						else
						{
							m_onMessageBegin(
								requestHeaders.c_str(), requestHeaders.size(),
								nullptr, 0, 
								responseHeaders.c_str(), responseHeaders.size(),
								nullptr, 0,
								&nextAction, &customBlockResponse, &customBlockResponseLen
							);

							switch (nextAction)
							{
								case 0:
								{
									// Allow without inspection, but if a response
									// comes, it is still wanted.
									request->SetShouldBlock(0);
									request->SetConsumeAllBeforeSending(false);

									if (response)
									{
										response->SetShouldBlock(0);
										response->SetConsumeAllBeforeSending(false);
									}

									return false;
								}
								break;

								case 1:
								{
									// Allow but want to inspect payload.
									request->SetShouldBlock(0);
									request->SetConsumeAllBeforeSending(true);

									if (response)
									{
										response->SetShouldBlock(0);
										response->SetConsumeAllBeforeSending(true);
									}
									return false;
								}
								break;

								case 2:
								{
									// Block.
									if (customBlockResponse != nullptr)
									{	
										std::vector<char> customPayloadVec(customBlockResponse, customBlockResponse + customBlockResponseLen);
										delete[] customBlockResponse;
										request->SetPayload(customPayloadVec, true);										
									}
									else
									{	
										request->Make204();
									}

									request->SetShouldBlock(1);

									if (response)
									{
										response->SetShouldBlock(1);										
									}
									return true;
								}
								break;

								case 3:
								{
									// Allow without inspection, for both request and a response.									
									// Setting to -1 will whitelist the rest of this transaction, 
									// including the response.
									request->SetShouldBlock(-1);
									request->SetConsumeAllBeforeSending(false);

									if (response)
									{
										response->SetShouldBlock(-1);
										response->SetConsumeAllBeforeSending(false);
									}
									return false;
								}
								break;
							}
						}

						return false;
					}
				};				

			} /* namespace secure */
		} /* namespace mitm */
	} /* namespace httpengine */
} /* namespace te */
