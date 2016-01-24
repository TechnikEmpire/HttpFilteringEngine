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

#include <boost/predef/architecture.h>
#include <boost/predef/os.h>
#include <boost/predef/compiler.h>
#include "../../network/SocketTypes.hpp"
#include "BaseInMemoryCertificateStore.hpp"
#include "../../filtering/http/HttpFilteringEngine.hpp"
#include "../http/HttpRequest.hpp"
#include "../http/HttpResponse.hpp"
#include "../../util/cb/EventReporter.hpp"
#include "../../../util/http/KnownHttpHeaders.hpp"
#include <memory>
#include <atomic>

#if BOOST_OS_WINDOWS

	#if BOOST_ARCH_X86_32
		#define cpu_relax()		asm volatile("pause" ::: "memory")
	#elif BOOST_ARCH_X86_64
		#define cpu_relax()		asm volatile("pause" ::: "memory")
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

namespace te
{
	namespace httpengine
	{
		namespace mitm
		{
			namespace secure
			{								

				/// <summary>
				/// The TlsCapableHttpBridge serves as the nice MITM for HTTP/HTTPS transactions.
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
				/// Since this class encorces TLS when serving a secure client, and parsing SNI is
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
				class TlsCapableHttpBridge : std::enable_shared_from_this< TlsCapableHttpBridge<BridgeSocketType> >, public util::cb::EventReporter
				{
					
				/// <summary>
				/// Enforce use of this class to the only two types of sockets it is intended to be
				/// used with.
				/// </summary>
				static_assert(
					(std::is_same<BridgeSocketType, network::TcpSocket> ::value || std::is_same<BridgeSocketType, network::TlsSocket>::value) &&
					u8"TlsCapableHttpBridge can only accept boost::asio::ip::tcp::socket or boost::asio::ssl::stream<boost::asio::ip::tcp::socket> as valid template parameters."
					);

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
					/// <param name="filteringEngine">
					/// A valid pointer to the filtering::http::HttpFilteringEngine object that will
					/// be used to filter HTTP transactions and payloads.
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
						const filtering::http::HttpFilteringEngine* filteringEngine,
						BaseInMemoryCertificateStore* certStore = nullptr,
						boost::asio::ssl::context* defaultServerContext = nullptr,
						boost::asio::ssl::context* clientContext = nullptr,
						util::cb::MessageFunction onInfoCb = nullptr,
						util::cb::MessageFunction onWarnCb = nullptr,
						util::cb::MessageFunction onErrorCb = nullptr
						) : 
						util::cb::EventReporter(onInfoCb, onWarnCb, onErrorCb);

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
					/// Every bridge requires a valid pointer to a filtering engine which may or may
					/// not be shared, for subjecting HTTP requests and responses to filtering.
					/// </summary>
					const filtering::http::HttpFilteringEngine* m_filteringEngine = nullptr;

					/// <summary>
					/// Pointer to the in memory certificate store that is required for TLS
					/// connections, to fetch and or generate certificates and corresponding server
					/// contexts as needed.
					/// </summary>
					BaseInMemoryCertificateStore* m_certStore;

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
					static constexpr size_t MinTlsHelloLength = 44;

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
					/// For supplying to async_read_until operations to force reads to stop at headers.
					/// </summary>
					static const std::string Crlf;		

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
							// This will force any pending async operations to stop and their completion
							// handlers to be called with operation_aborted as the error code.
							
							// XXX TODO - Perhaps we should use ReportWarning here instead of ReportError,
							// since the kinds of errors you usually get from these calls are non-fatal
							// issues. Usually just complaints about state etc.

							boost::system::error_code downstreamShutdownErr;
							boost::system::error_code downstreamCloseErr;
							boost::system::error_code upstreamShutdownErr;
							boost::system::error_code upstreamCloseErr;

							this->DownstreamSocket().shutdown(downstreamShutdownErr);
							this->DownstreamSocket().close(downstreamCloseErr);

							this->UpstreamSocket().shutdown(upstreamShutdownErr);
							this->UpstreamSocket().close(upstreamCloseErr);

							// We set the stream timeout to any negative value to force the stream
							// to have any pending async_wait's cancelled and the new timeout set to
							// positive infinity. This way, we don't have any unfinished async calls
							// on account of the timer that are preserving the lifetime of this object
							// unnecessarily via the shared_from_this that the handler(s) obtain(ed).
							SetStreamTimeout(-1);

							if (downstreamShutdownErr)
							{
								std::string err(u8"In TlsCapableHttpBridge<BridgeSocketType>::Kill() - When shutting down downstream socket, got error:\n\t");
								err.append(downstreamShutdownErr.message());
								ReportError(err);
							}

							if (downstreamCloseErr)
							{
								std::string err(u8"In TlsCapableHttpBridge<BridgeSocketType>::Kill() - When closing downstream socket, got error:\n\t");
								err.append(downstreamCloseErr.message());
								ReportError(err);
							}

							if (upstreamShutdownErr)
							{
								std::string dErrMessage(u8"In TlsCapableHttpBridge<BridgeSocketType>::Kill() - When shutting down upstream socket, got error:\n\t");
								dErrMessage.append(upstreamShutdownErr.message());
								ReportError(dErrMessage);
							}

							if (upstreamCloseErr)
							{
								std::string err(u8"In TlsCapableHttpBridge<BridgeSocketType>::Kill() - When closing upstream socket, got error:\n\t");
								err.append(upstreamCloseErr.message());
								ReportError(err);
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
						// EOF doesn't necessarily mean something critical happened. Could simply be
						// that we got the entire valid response, and the server closed the connection
						// after.
						if (!error || (error.value() == boost::asio::error::eof))
						{
							if (m_response->Parse(bytesTransferred))
							{
								auto blockResult = blockResult = m_filteringEngine->ShouldBlock(m_request.get(), m_response.get());								

								if (blockResult != 0)
								{
									// By setting ShouldBlock to a non-zero value, this adjusts the internal
									// state of the response to be "complete", meaning that as far as this
									// bridge is concerned, this transaction is finished. Setting shouldblock
									// **does not** make the response a 204 response. This needs to be done
									// explicitly.
									m_response->SetShouldBlock(blockResult);
									m_response->Make204();

									auto responseBuffer = m_response->GetWriteBuffer();

									boost::asio::async_write(
										m_downstreamSocket, 
										writeBuffer, 
										boost::asio::transfer_all(), 
										m_downstreamStrand.wrap(
											std::bind(
												&TlsCapableHttpBridge::OnDownstreamWrite, 
												shared_from_this(), 
												boost::asio::placeholders::error
												)
											)
										);

									return;
								}

								// We want to remove any header that has to do with Google's SDHC
								// compression method. We don't want it, because we don't support it
								// so we'd have no way to handle content compressed with this method.
								m_response->RemoveHeader(util::http::headers::GetDictionary);

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

								if (m_response->IsPayloadHtml())
								{
									// We filter with CSS filters, so we want to consume entire HTML responses before
									// sending them back to the client, so we can filter them first.
									m_response->SetConsumeAllBeforeSending(true);
								}

								if (m_response->IsPayloadComplete() == false && m_response->GetConsumeAllBeforeSending() == true)
								{
									// We need to reinitiate sequential reads of the response
									// payload until we have all of the response body, as it has
									// been marked for inspection.

									// We do this in a try/catch because getting the read buffer for the payload
									// can throw if the maximum payload size has been reached. This is defined as
									// a constexpr in BaseHttpTransaction. 
									try
									{
										auto readBuffer = m_response->GetPayloadReadBuffer();

										SetStreamTimeout(5000);

										boost::asio::async_read(
											m_upstreamSocket,
											readBuffer,
											boost::asio::transfer_at_least(1),
											m_upstreamStrand.wrap(
												std::bind(
													&TlsCapableHttpBridge::OnUpstreamRead,
													shared_from_this(),
													boost::asio::placeholders::error,
													boost::asio::placeholders::bytes_transferred
													)
												)
											);

										return;
									}
									catch (std::runtime_error& e)
									{
										ReportError(e.what());
									}									
								}
								else
								{
									// We need to write what we have to the client.

									SetStreamTimeout(5000);

									auto writeBuffer = m_response->GetWriteBuffer();

									boost::asio::async_write(
										m_downstreamSocket,
										writeBuffer,
										boost::asio::transfer_all(),
										m_downstreamStrand.wrap(
											std::bind(
												&TlsCapableHttpBridge::OnDownstreamWrite,
												shared_from_this(),
												boost::asio::placeholders::error
												)
											)
										);

									return;
								}								
							}
							else
							{
								ReportError(u8"In TlsCapableHttpBridge::OnUpstreamHeaders(const boost::system::error_code&, const size_t) - \
									Failed to parse response.");
							}							
						}
						else
						{
							std::string errMsg(u8"In TlsCapableHttpBridge::OnUpstreamHeaders(const boost::system::error_code&, const size_t) - Got error:\n\t");
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
						// EOF doesn't necessarily mean something critical happened. Could simply be
						// that we got the entire valid response, and the server closed the connection
						// after.

						// We don't need to do any blocking or block checks in this method, to determine if the
						// request itself should be blocked. This should have already been done as soon as the
						// upstream headers were read, since all data that can possibly be used to determine
						// if a block should take place would have been available there. So if we're even in this
						// far, we only look for HTML content we can run CSS selectors on.
						if (!error || (error.value() == boost::asio::error::eof))
						{
							if (m_response->Parse(bytesTransferred))
							{
								// Let CSS selectors rip through the payload if it's complete and its HTML.
								if (m_response->IsPayloadComplete() && m_response->GetConsumeAllBeforeSending() && m_response->IsPayloadHtml())
								{
									auto processedHtmlString = m_filteringEngine->ProcessHtmlResponse(m_request.get(), m_response.get());

									std::vector<char> processedHtmlVector(processedHtmlString.begin(), processedHtmlString.end());

									m_response->SetPayload(processedHtmlVector);
								}
								else if (m_response->IsPayloadComplete() == false && m_response->GetConsumeAllBeforeSending() == true)
								{
									SetStreamTimeout(5000);

									auto readBuffer = m_response->GetPayloadReadBuffer();

									boost::asio::async_read(
										m_upstreamSocket, 
										readBuffer, 
										boost::asio::transfer_at_least(1), 
										m_upstreamStrand.wrap(
											std::bind(
												&TlsCapableHttpBridge::OnUpstreamRead, 
												shared_from_this(), 
												boost::asio::placeholders::error, 
												boost::asio::placeholders::bytes_transferred
												)
											)
										);

									return;
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
											boost::asio::placeholders::error
											)
										)
									);
								
								return;
							}
							else
							{
								ReportError(u8"In TlsCapableHttpBridge::OnUpstreamRead(const boost::system::error_code&, const size_t) - \
									Failed to parse response.");
							}
						}
						else
						{
							std::string errMsg(u8"In TlsCapableHttpBridge::OnUpstreamRead(const boost::system::error_code&, const size_t) - Got error:\n\t");
							errMsg.append(error.message());
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
						// EOF doesn't necessarily mean something critical happened. Could simply be
						// that we got the entire valid response, and the server closed the connection
						// after.
						if (!error)
						{
							if (m_request->IsPayloadComplete() == false)
							{
								// The client has more to write to the server.

								SetStreamTimeout(5000);

								auto readBuffer = m_request->GetPayloadReadBuffer();

								boost::asio::async_read(
									m_downstreamSocket, 
									readBuffer, 
									boost::asio::transfer_at_least(1), 
									m_downstreamStrand.wrap(
										std::bind(
											&TlsCapableHttpBridge::OnDownstreamRead, 
											shared_from_this(), 
											boost::asio::placeholders::error, 
											boost::asio::placeholders::bytes_transferred
											)
										)
									);

								return;
							}
							else
							{
								// Client is all done, get the response headers.

								SetStreamTimeout(5000);

								boost::asio::async_read_until(
									m_upstreamSocket, 
									m_response->GetHeaderReadBuffer(), 
									Crlf,
									m_upstreamStrand.wrap(
										std::bind(
											&TlsCapableHttpBridge::OnUpstreamHeaders, 
											shared_from_this(), 
											boost::asio::placeholders::error, 
											boost::asio::placeholders::bytes_transferred
											)
										)
									);

								return;
							}
						}
						else
						{
							std::string errMsg(u8"In TlsCapableHttpBridge::OnUpstreamWrite(const boost::system::error_code&) - Got error:\n\t");
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
					void OnDownstreamHeaders(const boost::system::error_code& error, const size_t bytesTansferred)
					{
						// EOF doesn't necessarily mean something critical happened. Could simply be
						// that we got the entire valid response, and the server closed the connection
						// after.
						if (!error || (error.value() == boost::asio::error::eof))
						{
							if (m_request->Parse(bytesTransferred))
							{								
								m_request->SetShouldBlock(m_filteringEngine->ShouldBlock(m_request.get()));

								// This little business is for dealing with browsers like Chrome, who just have
								// to use their own "I'm too cool for skool" compression methods like SDHC. We
								// want to be sure that we get normal, non-hipster encoded, non-organic smoothie
								// encoded reponses that sane people can decompress. So we just always replace
								// the Accept-Encoding header with this.
								std::string standardEncoding(u8"gzip, deflate");
								m_request->AddHeader(util::http::headers::AcceptEncoding, standardEncoding);

								// Modifying content-encoding isn't enough for that sweet organic spraytanned
								// browser Chrome and its server cartel buddies. If these special headers make
								// it through, even though we've explicitly defined our accepted encoding,
								// you're still going to get SDHC encoded data.
								m_request->RemoveHeader(util::http::headers::XSDHC);
								m_request->RemoveHeader(util::http::headers::AvailDictionary);

								auto hostHeader = m_request->GetHeader(util::http::headers::Host);

								if (hostHeader.first != hostHeader.second)
								{
									auto hostWithoutPort = hostHeader.first->second;

									boost::trim(hostWithoutPort);

									auto portInd = hostWithoutPort.find(':');

									if (portInd != std::string::npos)
									{
										hostWithoutPort = hostWithoutPort.substr(0, portInd);
										
										auto portString = hostWithoutPort.substr(portInd + 1);

										try
										{
											m_upstreamHostPort = static_cast<uint16_t>(std::stoi(portString));
										}
										catch (...)
										{
											// We don't really care what went wrong. We failed to parse the port in the host. We'll
											// simply issue a warning, and assume port 80.
											ReportWarning(u8"In TlsCapableHttpBridge::OnDownstreamHeaders(const boost::system::error_code&, const size_t) - \
												Failed to parse port in host entry. Assuming port 80.");
										}										
									}								
									
									
									auto hostComparison = hostWithoutPort.compare(m_upstreamHost);
									if (m_upstreamHost.size() == 0 || (hostComparison == 0 && m_keepAlive == false))
									{

										// In the event that the upstream host name is empty, or that it's equal to the request
										// host but keep-alive is set to false, then we need to establish a new connection to 
										// the host in question. We'll do this by simply resolving the host. The resolve handler
										// will take it from there.

										SetStreamTimeout(5000);

										m_upstreamHost = hostWithoutPort;
										boost::asio::ip::tcp::resolver::query query(m_upstreamHost, "http");

										m_resolver.async_resolve(
											query,
											m_upstreamStrand.wrap(
												std::bind(
													&TlsCapableHttpBridge::OnResolve,
													shared_from_this(),
													boost::asio::placeholders::error,
													boost::asio::placeholders::iterator
													)
												)
											);

										return;										
									}
									else if (hostComparison == 0 && m_keepAlive == true)
									{
										// Just write to the server that we're apparently already connected to. We
										// don't concern ourselves with the ShouldBlock value here on the request.
										// Once we get the upstream response headers, which gives us data about the
										// size of a yet-to-be-completed request, we will block if the value was set
										// here, but not before the http filtering engine reports this data to
										// any observer(s).

										SetStreamTimeout(5000);

										boost::asio::async_write(
											m_upstreamSocket, 
											writeBuffer, 
											boost::asio::transfer_all(), 
											m_upstreamStrand.wrap(
												std::bind(
													&TlsCapableHttpBridge::OnUpstreamWrite, 
													shared_from_this(), 
													boost::asio::placeholders::error
													)
												)
											);

										return;
									}
									
									// Host is defined but is different than the requested host.
									// Need to let this die. Not an error, nothing to even warn about.
								}
								else
								{
									ReportError(u8"In TlsCapableHttpBridge::OnDownstreamHeaders(const boost::system::error_code&, const size_t) - \
										Failed to read Host header from request.");
								}
							}
							else
							{
								ReportError(u8"In TlsCapableHttpBridge::OnDownstreamHeaders(const boost::system::error_code&, const size_t) - \
									Failed to parse request.");
							}
						}
						else
						{
							std::string errMsg(u8"In TlsCapableHttpBridge::OnDownstreamHeaders(const boost::system::error_code&, const size_t) - Got error:\n\t");
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
						// EOF doesn't necessarily mean something critical happened. Could simply be
						// that we got the entire valid response, and the server closed the connection
						// after.
						if (!error || (error.value() == boost::asio::error::eof))
						{
							if (m_request->Parse(bytesTransferred))
							{
								if (m_request->IsPayloadComplete() == false && m_request->GetConsumeAllBeforeSending())
								{
									// The client has more to send and it's been flagged for inspection. Must
									// initiate a read again.

									SetStreamTimeout(5000);

									auto readBuffer = m_request->GetPayloadReadBuffer();

									boost::asio::async_read(
										m_downstreamSocket, 
										readBuffer, 
										boost::asio::transfer_at_least(1), 
										m_downstreamStrand.wrap(
											std::bind(
												&TlsCapableHttpBridge::OnDownstreamRead, 
												shared_from_this(), 
												boost::asio::placeholders::error, 
												boost::asio::placeholders::bytes_transferred
												)
											)
										);

									return;
								}

								SetStreamTimeout(5000);

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
											boost::asio::placeholders::error
											)
										)
									);

								return;
							}
							else
							{
								ReportError(u8"In TlsCapableHttpBridge::OnDownstreamHeaders(const boost::system::error_code&, const size_t) - \
									Failed to parse request.");
							}
						}
						else
						{
							std::string errMsg(u8"In TlsCapableHttpBridge::OnDownstreamRead(const boost::system::error_code&, const size_t) - Got error:\n\t");
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
						// EOF doesn't necessarily mean something critical happened. Could simply be
						// that we got the entire valid response, and the server closed the connection
						// after.
						if (!error)
						{
							if (m_response->IsPayloadComplete() == false)
							{
								// The server has more to write.

								SetStreamTimeout(5000);

								auto readBuffer = m_response->GetPayloadReadBuffer();

								boost::asio::async_read(
									m_upstreamSocket, 
									readBuffer, 
									boost::asio::transfer_at_least(1), 
									m_upstreamStrand.wrap(
										std::bind(
											&TlsCapableHttpBridge::OnUpstreamRead,
											shared_from_this(), boost::asio::placeholders::error, 
											boost::asio::placeholders::bytes_transferred
											)
										)
									);
								
								return;
							}

							// We've fulfilled the request. Now, if keep-alive was specified, we'll reset and
							// start over again. Otherwise, we'll just die.
							if (m_keepAlive)
							{
								SetStreamTimeout(5000);

								m_request.reset(new http::HttpRequest());
								m_response.reset(new http::HttpResponse());

								boost::asio::async_read_until(
									m_downstreamSocket, 
									m_request->GetHeaderBuffer(), 
									CrLf, 
									m_downstreamStrand.wrap(
										std::bind(
											&TlsCapableHttpBridge::OnDownstreamHeaders, 
											shared_from_this(), 
											boost::asio::placeholders::error, 
											boost::asio::placeholders::bytes_transferred
											)
										)
									);

								return;
							}
						}
						else
						{
							std::string errMsg(u8"In TlsCapableHttpBridge::OnDownstreamWrite(const boost::system::error_code&) - Got error:\n\t");
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
						if (error)
						{
							if (error.value() == boost::asio::error::operation_aborted)
							{
								// Aborts are normal, as pending async_waits are cancelled every time that
								// the timeout is reset. Therefore, we safely ignore them.
								return;
							}
							else
							{
								// XXX TODO - Perhaps in the event of an error, we should return and avoid
								// calling ::Kill()?
								std::string errMessage(u8"In TlsCapableHttpBridge<BridgeSocketType>::OnStreamTimeout(const boost::system::error_code&) - Got error:\n\t");
								errMessage.append(error.message());
								ReportError(errMessage);
							}
						}

						ReportWarning(u8"In TlsCapableHttpBridge<BridgeSocketType>::OnStreamTimeout(const boost::system::error_code&) - Stream timed out.");

						Kill();
					}

					/// <summary>
					/// Sets or resets the timeout for the bridge's stream operations. If the
					/// timeout is reached and the completion handler invoked, then the bridge will
					/// be killed, with both downstream and upstream operations cancelled in an
					/// asynchrous manner, at which time the bridge's reference count will reach
					/// zero and the destructor will be called.
					/// </summary>
					/// <param name="millisecondsFromNow">
					/// The number of milliseconds from now until the timeout. If any negative value
					/// is supplied, the timeout will be set to positive infinity, so it never expires.
					/// </param>
					void SetStreamTimeout(int millisecondsFromNow)
					{
						m_streamTimer.cancel();

						if (millisecondsFromNow < 0)
						{
							m_streamTimer.expires_at(boost::posix_time::pos_infin);
							return;
						}
						
						m_streamTimer.async_wait(boost::bind(&TlsCapableHttpBridge::OnStreamTimeout, shared_from_this(), boost::asio::placeholders::error));
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
						if (!error && m_upstreamCert != nullptr)
						{
							
						}
						else
						{
							if (error)
							{
								std::string errMsg(u8"In TlsCapableHttpBridge<network::TlsSocket>::OnUpstreamHandshake(const boost::system::error_code&) - Got error:\n\t");
								errMsg.append(error.message());
								ReportError(errMessage);
							}

							if (m_upstreamCert != nullptr)
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

						if (!error && bytesTransferred > 0)
						{
							boost::string_ref hostName;

							size_t pos = 0;
							if (m_tlsPeekBuffer != nullptr && (bytesTransferred > MinTlsHelloLength))
							{
								// Handshake && client hello
								if (m_tlsPeekBuffer[0] == 0x16 && (m_tlsPeekBuffer[5] == 0x01))
								{
									pos = 5;

									int helloLen = 
										(reinterpret_cast<unsigned char>(m_tlsPeekBuffer[++pos]) << 16) + 
										(reinterpret_cast<unsigned char>(m_tlsPeekBuffer[++pos]) << 8) + 
										reinterpret_cast<unsigned char>(m_tlsPeekBuffer[++pos]);

									// Skip random bytes.
									pos += 32;

									// Skip past Session ID Length.
									pos += static_cast<size_t>(m_tlsPeekBuffer[pos]);

									int cipherSuitesLen = 
										(reinterpret_cast<unsigned char>(m_tlsPeekBuffer[pos]) << 8) +
										reinterpret_cast<unsigned char>(m_tlsPeekBuffer[++pos]);

									pos += static_cast<size_t>(cipherSuitesLen);

									// Skip past NULL-MD5, renegotation nfo.
									pos += 4;

									// Skip past Compression Methods Length.
									pos += static_cast<size_t>(m_tlsPeekBuffer[pos]);

									int extensionsLen = (reinterpret_cast<unsigned char>(m_tlsPeekBuffer[pos]) << 8) + reinterpret_cast<unsigned char>(m_tlsPeekBuffer[++pos]);

									// In case we didn't get the whole hello, adjust our bounds.
									extensionsLen = std::min(extensionsLen, static_cast<int>(bytesTransferred));

									bool notDone = true;
									int extensionPos = static_cast<int>(pos);
									bool isSni = false;
									while((extensionPos + 1) < extensionsLen && notDone)
									{
										
										if (m_tlsPeekBuffer[extensionPos] == 0x00 && m_tlsPeekBuffer[extensionPos + 1] == 0x00)
										{
											isSni = true;											
										}	

										extensionPos += 2;

										if (extensionPos < extensionsLen && (extensionPos + 1) < extensionsLen)
										{
											// If we're in-bounds, get the length of the extension.		
											int thisExtensionLen =
												(reinterpret_cast<unsigned char>(m_tlsPeekBuffer[extensionPos]) << 8) +
												reinterpret_cast<unsigned char>(m_tlsPeekBuffer[extensionPos + 1]);

											extensionPos += 2;

											if!(isSni)
											{
												// Skip this much, since we don't have our SNI extension yet.
												extensionPos += thisExtensionLen;
												continue;
											}

											// Is SNI extension, but extension is multipart. Want only the portion of the
											// extension that contains the actual hostname.
											while ((extensionPos + 3) < thisExtensionLen && (extensionPos + 3) < extensionsLen && !notDone)
											{
												int sniPartLen = (reinterpret_cast<unsigned char>(m_tlsPeekBuffer[extensionPos + 1]) << 8) +
													reinterpret_cast<unsigned char>(m_tlsPeekBuffer[extensionPos + 2]);


												auto sniExtensionType = m_tlsPeekBuffer[extensionPos];
												extensionPos += 3;

												switch (sniExtensionType)
												{
													case 0x00:
													{
														if (extensionPos + sniPartLen <= extensionsLen)
														{
															// If we're in bounds including our length, then we've got the entire hostname.
															hostName = boost::string_ref(m_tlsPeekBuffer[extensionPos], sniPartLen);
														}
														else
														{
															ReportWarning(u8"In TlsCapableHttpBridge<network::TlsSocket>::OnTlsPeek(const boost::system::error_code&, const size_t) - \
																Discovered SNI hostname entry, but entire entry was not read into the peek buffer.");
														}

														notDone = false;
														break;
													}
													break;

													default:
														ReportWarning(u8"In TlsCapableHttpBridge<network::TlsSocket>::OnTlsPeek(const boost::system::error_code&, const size_t) - \
															Skipping unknown SNI extension part.");
												}

												extensionPos += sniPartLen;
											}
										}

										notDone = false;
									}

									if (hostName.data() != nullptr && hostName.size() > 0)
									{
										// If we have a hostname, then we need to resolve it and let the specialized OnResolve method
										// take over to correctly initiate the process of verifying the upstream requested server/host
										// and certificate, fetching or generating a context, etc.

										m_upstreamHost = hostName.to_string();

										// XXX TODO - See notes in the version of ::OnResolve(...), specializedd for TLS clients.
										m_upstreamHostPort = 443;

										try
										{	
											boost::asio::ip::tcp::resolver::query query(m_upstreamHost, "https");
											m_resolver.async_resolve(query, m_upstreamStrand.wrap(boost::bind(&TlsCapableHttpBridge::OnResolve, shared_from_this(), boost::asio::placeholders::error, boost::asio::placeholders::iterator)));
											return;
										}
										catch (std::exception& e)
										{
											std::string errorMessage(u8"In TlsCapableHttpBridge<network::TlsSocket>::OnTlsPeek(const boost::system::error_code&, const size_t) - Got Error:\n\t");
											errorMessage.append(e.message());
											ReportError(errorMessage);
										}
									}

									ReportError(u8"In TlsCapableHttpBridge<network::TlsSocket>::OnTlsPeek(const boost::system::error_code&, const size_t) - \
										Failed to extract hostname from SNI extension.");
								}
								else
								{
									// Not TLS client hello.
									ReportWarning(u8"In TlsCapableHttpBridge<network::TlsSocket>::OnTlsPeek(const boost::system::error_code&, const size_t) - \
									 Peeked data is not TLS client hello.");
								}
							}
							else
							{
								// TLS peek buffer is nullptr or bytesTransferred is less than or equal to MinTlsHelloLength
								if (!m_tlsPeekBuffer)
								{
									ReportError(u8"In TlsCapableHttpBridge<network::TlsSocket>::OnTlsPeek(const boost::system::error_code&, const size_t) - \
									 m_tlsPeekBuffer is nullptr!");
								}
								else
								{
									ReportWarning(u8"In TlsCapableHttpBridge<network::TlsSocket>::OnTlsPeek(const boost::system::error_code&, const size_t) - \
									 Peeked data is not sufficient in length to be a TLS client hello.");
								}
							}
						}
						else
						{
							// Error is set or bytesTransferred is 0
							if (error)
							{
								std::string errorMessage(u8"In TlsCapableHttpBridge<network::TlsSocket>::OnTlsPeek(const boost::system::error_code&, const size_t) - Got Error:\n\t");
								errorMessage.append(error.message());
								ReportError(errorMessage);
							}
							else
							{
								ReportWarning(u8"In TlsCapableHttpBridge<network::TlsSocket>::OnTlsPeek(const boost::system::error_code&, const size_t) - \
									 Peeked data length is zero.");
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
						boost::asio::ssl::rfc2818_verification v(m_currentHost);

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
								X509_NAME_oneline(X509_get_subject_name(curCert), subject_name, MaxDomainNameSize);
								
								std::string verifyFailedErrorMessage("In TlsCapableHttpBridge<network::TlsSocket>::VerifyServerCertificateCallback(bool, boost::asio::ssl::verify_context&) - Cert for ");																
								verifyFailedErrorMessage.append(subjectName);
								verifyFailedErrorMessage.append(u8" failed verification.");
								
								ReportError(verifyFailedErrorMessage);
							}

							m_upstreamCert = nullptr;
						}

						return verified;
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
							std::string errorMessage(u8"In TlsCapableHttpBridge<BridgeSocketType>::SetLinger(boost::asio::ip::tcp::socket&, const bool) - \
								While setting linger state, got error:\n\t");
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
							std::string errorMessage(u8"In TlsCapableHttpBridge<BridgeSocketType>::SetNoDelay(boost::asio::ip::tcp::socket&, const bool) - \
								While setting Nagle algorithm enabled state, got error:\n\t");
							errorMessage.append(err.message());
							ReportError(errorMessage);
						}
					}

				};

				template<class BridgeSocketType>
				const std::string TlsCapableHttpBridge::<BridgeSocketType>::Crlf{u8"\r\n\r\n"};

			} /* namespace secure */
		} /* namespace mitm */
	} /* namespace httpengine */
} /* namespace te */
