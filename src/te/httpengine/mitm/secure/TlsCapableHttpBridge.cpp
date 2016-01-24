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

#include "TlsCapableHttpBridge.hpp"
#include <stdexcept>

namespace te
{
	namespace httpengine
	{
		namespace mitm
		{
			namespace secure
			{					
				
				TlsCapableHttpBridge<network::TcpSocket>::TlsCapableHttpBridge(
					boost::asio::io_service* service,					
					const filtering::http::HttpFilteringEngine* filteringEngine,
					BaseInMemoryCertificateStore* certStore,
					boost::asio::ssl::context* defaultServerContext,
					boost::asio::ssl::context* clientContext,
					util::cb::MessageFunction onInfoCb,
					util::cb::MessageFunction onWarnCb,
					util::cb::MessageFunction onErrorCb
					) : 
					m_upstreamSocket(*service), 
					m_downstreamSocket(*service),
					m_upstreamStrand(*service),
					m_downstreamStrand(*service),
					m_resolver(*service),
					m_streamTimer(*service),				
					m_filteringEngine(filteringEngine),
					m_certStore(certStore)				
				{
					#ifndef NDEBUG						
						assert(m_filteringEngine != nullptr && u8"In TlsCapableHttpBridge<network::TcpSocket>::TlsCapableHttpBridge(... args) - Supplied filtering engine pointer is nullptr!");
					#else
						if (m_filteringEngine == nullptr)
						{
							throw new std::runtime_error(u8"In TlsCapableHttpBridge<network::TcpSocket>::TlsCapableHttpBridge(... args) - Supplied filtering engine pointer is nullptr!");
						}
					#endif
					

					m_request.reset(new http::HttpRequest());
					m_response.reset(new http::HttpResponse());
				}
				
				TlsCapableHttpBridge<network::TlsSocket>::TlsCapableHttpBridge(
					boost::asio::io_service* service,					
					const filtering::http::HttpFilteringEngine* filteringEngine,
					BaseInMemoryCertificateStore* certStore,
					boost::asio::ssl::context* defaultServerContext,
					boost::asio::ssl::context* clientContext,
					util::cb::MessageFunction onInfoCb,
					util::cb::MessageFunction onWarnCb,
					util::cb::MessageFunction onErrorCb
					)
					:
					m_upstreamSocket(*service, *clientContext),
					m_downstreamSocket(*service, *defaultServerContext),
					m_upstreamStrand(*service),
					m_downstreamStrand(*service),
					m_resolver(*service),
					m_streamTimer(*service),					
					m_filteringEngine(filteringEngine),
					m_certStore(certStore)
				{
					#ifndef NDEBUG					
						assert(m_filteringEngine != nullptr && u8"In TlsCapableHttpBridge<network::TlsSocket>::TlsCapableHttpBridge(... args) - Supplied certificate store is nullptr!");
						assert(m_certStore != nullptr && u8"In TlsCapableHttpBridge<network::TlsSocket>::TlsCapableHttpBridge(... args) - Supplied certificate store is nullptr!");						
					#else
						if (m_filteringEngine == nullptr)
						{
							throw new std::runtime_error(u8"In TlsCapableHttpBridge<network::TlsSocket>::TlsCapableHttpBridge(... args) - Supplied filtering engine pointer is nullptr!");
						}

						if (m_certStore == nullptr)
						{
							throw new std::runtime_error(u8"In TlsCapableHttpBridge<network::TlsSocket>::TlsCapableHttpBridge(... args) - Supplied certificate store is nullptr!");
						}
					#endif
					

					m_request.reset(new http::HttpRequest());
					m_response.reset(new http::HttpResponse());
					m_tlsPeekBuffer.reset(new std::array<char, TlsPeekBufferSize>());										
				}

				template<>
				void TlsCapableHttpBridge<network::TcpSocket>::Start()
				{
					try
					{
						SetStreamTimeout(10000);

						// We start off by simply reading the client request headers.
						boost::asio::async_read_until(
							m_downstreamSocket, 
							m_request->GetHeaderReadBuffer(), 
							Crlf, 
							m_downstreamStrand.wrap(
								std::bind(
									&TlsCapableHttpBridge::OnDownstreamHeaders, 
									shared_from_this(), 
									boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred
									)
								)
							);

						return;
					}
					catch (std::exception& e)
					{
						std::string errMessage(u8"IN TlsCapableHttpBridge<network::TcpSocket>::Start() - Got error:\n\t");
						errMessage.append(e.what());
						ReportError(errMessage);
					}

					Kill();
				}

				template<>
				void TlsCapableHttpBridge<network::TlsSocket>::Start()
				{					
					try
					{
						SetStreamTimeout(10000);

						// Start a peek read on the connected secure client, so we can attempt to extract the
						// SNI hostname in the handler without screwing up the pending handshake.
						m_downstreamSocket.next_layer().async_receive(
							boost::asio::buffer(*m_tlsPeekBuffer.get(), m_tlsPeekBuffer->size()), 
							boost::asio::ip::tcp::socket::message_peek, 
							m_downstreamStrand.wrap(
								std::bind(&TlsCapableHttpBridge::OnTlsPeek, 
									shared_from_this(), 
									boost::asio::placeholders::error, 
									boost::asio::placeholders::bytes_transferred
									)
								)
							);

						return;
					}
					catch (std::exception& e)
					{
						std::string errMessage(u8"IN TlsCapableHttpBridge<network::TlsSocket>::Start() - Got error:\n\t");
						errMessage.append(e.what());						
						ReportError(errMessage);
					}

					Kill();
				}

				template<>
				boost::asio::ip::tcp::socket& TlsCapableHttpBridge<network::TcpSocket>::DownstreamSocket()
				{
					return m_downstreamSocket;
				}

				template<>
				boost::asio::ip::tcp::socket& TlsCapableHttpBridge<network::TlsSocket>::DownstreamSocket()
				{
					return m_downstreamSocket.next_layer();
				}

				template<>
				boost::asio::ip::tcp::socket& TlsCapableHttpBridge<network::TcpSocket>::UpstreamSocket()
				{
					return m_upstreamSocket;
				}

				template<>
				boost::asio::ip::tcp::socket& TlsCapableHttpBridge<network::TlsSocket>::UpstreamSocket()
				{
					return m_upstreamSocket.next_layer();
				}

				template<>
				void TlsCapableHttpBridge<network::TcpSocket>::OnUpstreamConnect(const boost::system::error_code& error)
				{

					if (!error)
					{
						SetNoDelay(UpstreamSocket(), true);
						SetNoDelay(DownstreamSocket(), true);

						if (m_request->IsPayloadComplete() == false && m_request->GetConsumeAllBeforeSending() == true)
						{
							// Means that there is a request payload, it's not complete, and it's been flagged
							// for inspection before being sent upstream. Another read from the client is
							// required.

							auto requestReadBuffer = m_request->GetPayloadReadBuffer();

							boost::asio::async_read(
								m_downstreamSocket, 
								requestReadBuffer, 
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

						// Means that we need to start off by simply writing whatever we've got from the client to 
						// the server. In the completion handler for this op, it will be determined if the client
						// has more to give or not, and this will be handled correctly.

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
						std::string errMsg(u8"In TlsCapableHttpBridge<network::TlsSocket>::OnUpstreamConnect(const boost::system::error_code&) - \
							Got error:\n\t");
						errMsg.append(error.message());
						ReportError(errMsg);
					}
					
					Kill();
				}

				template<>
				void TlsCapableHttpBridge<network::TlsSocket>::OnUpstreamConnect(const boost::system::error_code& error)
				{
					if (!error)
					{
						SetNoDelay(UpstreamSocket(), true);
						SetNoDelay(DownstreamSocket(), true);

						SetStreamTimeout(5000);

						m_upstreamSocket.set_verify_mode(boost::asio::ssl::verify_peer | boost::asio::ssl::verify_fail_if_no_peer_cert);

						boost::system::error_code scerr;

						// Verification callback does not require a shared_ptr for the bind, because the async_handshake
						// completion handler will "out-live" the verification callback, so it will hold the shared_ptr
						// that will ensure this object survives the async handshake.

						m_upstreamSocket.set_verify_callback(
							std::bind(
								&TlsCapableHttpBridge::VerifyServerCertificateCallback, 
								this, 
								std::placeholders::_1, 
								std::placeholders::_2
								), 
							scerr
							);

						if (!scerr)
						{
							m_upstreamSocket.async_handshake(
								network::TlsSocket::client, 
								m_upstreamStrand.wrap(
									std::bind(
										&TlsCapableHttpBridge::OnUpstreamHandshake, 
										shared_from_this(), 
										boost::asio::placeholders::error
										)
									)
								);

							return;
						}
						else
						{
							std::string errMsg(u8"In TlsCapableHttpBridge<network::TlsSocket>::OnUpstreamConnect(const boost::system::error_code&) - \
							While setting verification callback, got error:\n\t");
							errMsg.append(error.message());
							ReportError(errMsg);
						}
					}
					else
					{
						std::string errMsg(u8"In TlsCapableHttpBridge<network::TlsSocket>::OnUpstreamConnect(const boost::system::error_code&) - \
							Got error:\n\t");
						errMsg.append(error.message());
						ReportError(errMsg);
					}

					Kill();
				}

				template<>
				void TlsCapableHttpBridge<network::TcpSocket>::OnResolve(const boost::system::error_code& error, boost::asio::ip::tcp::resolver::iterator endpointIterator)
				{
					if (!error)
					{

						SetStreamTimeout(5000);

						auto ep = *endpointIterator;

						// Perhaps client requested a port other than 80. We should have already parsed
						// this before initiating the resolve of the upstream host, so that this information
						// was not polluting the hostname during resolution.
						//
						// RFC2616 Section 14.23 demands that non-port-80 requests include the port in with
						// the host name, so this should be reliable. If m_upstreamHostPort is zero, the 
						// default value, then we leave the configured port alone, because we resolved this
						// using "http" as the service parameter on the resolver. The service parameter consults
						// something unknown to me (I vaguely remember the details) which has a list of port
						// numbers associated with specific services. So by default, every iterator result
						// here should be preconfigured to port 80.
						if (m_upstreamHostPort != 0 && ep.endpoint().port() != m_upstreamHostPort)
						{
							ep.endpoint().port(m_upstreamHostPort);
						}

						// XXX TODO. The correct thing to do here is keep the iterator somehow, then in
						// the completion handler, in the event of a connection related error, keep
						// incrementing through the iterator until all possible endpoints for the
						// requested host have been exhausted. Doing things this way means that we
						// only take a crack at connecting to the first A record entry resolved, then
						// quit if that first record does not work.

						m_upstreamSocket.async_connect(
							ep, 
							m_upstreamStrand.wrap(
								std::bind(
									&TlsCapableHttpBridge::OnUpstreamConnect, 
									shared_from_this(), 
									boost::asio::placeholders::error
									)
								)
							);

						return;
					}
					else
					{
						std::string errMsg(u8"In TlsCapableHttpBridge<network::TcpSocket>::OnResolve(const boost::system::error_code&, boost::asio::ip::tcp::resolver::iterator) - \
							Got error:\n\t");
						errMsg.append(error.message());
						ReportError(errMsg);
					}

					Kill();
				}

				template<>
				void TlsCapableHttpBridge<network::TlsSocket>::OnResolve(const boost::system::error_code& error, boost::asio::ip::tcp::resolver::iterator endpointIterator)
				{
					if (!error)
					{

						SetStreamTimeout(5000);

						SSL_set_tlsext_host_name(m_upstreamSocket.native_handle(), m_upstreamHost.c_str());

						// XXX TODO. The correct thing to do here is keep the iterator somehow, then in
						// the completion handler, in the event of a connection related error, keep
						// incrementing through the iterator until all possible endpoints for the
						// requested host have been exhausted. Doing things this way means that we
						// only take a crack at connecting to the first A record entry resolved, then
						// quit if that first record does not work.

						// Note also that unlike the TCP version of this handler, we do not check the
						// upstream host member for a port number. This is because, AFAIK, there is no
						// such data in the SNI extension, the place where we get the hostname from.
						//
						// This could become a problem only depending on our implementation in the 
						// packet diversion system. If we intercept TLS packets that are not destined
						// for 443 and send them to this proxy, then we'll break the connection entirely.
						// Care therefore needs to be taken, or a more robust system needs to be put in
						// place starting at the diversion level.

						m_upstreamSocket.lowest_layer().async_connect(
							*endpointIterator,
							m_upstreamStrand.wrap(
								std::bind(
									&TlsCapableHttpBridge::OnUpstreamConnect, 
									shared_from_this(), 
									boost::asio::placeholders::error
									)
								)
							);

						return;
					}
					else
					{
						std::string errMsg(u8"In TlsCapableHttpBridge<network::TlsSocket>::OnResolve(const boost::system::error_code&, boost::asio::ip::tcp::resolver::iterator) - \
							Got error:\n\t");
						errMsg.append(error.message());
						ReportError(errMsg);
					}

					Kill();
				}				

			} /* namespace secure */
		} /* namespace mitm */
	} /* namespace httpengine */
} /* namespace te */