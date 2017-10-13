/*
* Copyright © 2017 Jesse Nicholson
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

#include "TlsCapableHttpBridge.hpp"
#include <http/client/x509_cert_utilities.h>
#include <stdexcept>

namespace te
{
	namespace httpengine
	{
		namespace mitm
		{
			namespace secure
			{	
				template <typename T>
				std::unordered_map<std::string, std::unique_ptr<boost::asio::ssl::context>, util::hash::ICaseStringHash, util::hash::ICaseStringEquality>  TlsCapableHttpBridge<T>::s_clientContexts;

				template <typename T>
				std::atomic_flag TlsCapableHttpBridge<T>::s_clientContextLock = ATOMIC_FLAG_INIT;

                template <typename T>
                constexpr uint32_t TlsCapableHttpBridge<T>::s_streamChannelMultiplier = 10;

                template <typename T>
                util::cb::CStreamCopyUtilContainer<std::is_same<T, network::TlsSocket>::value, TlsCapableHttpBridge<T>::s_streamChannelMultiplier> TlsCapableHttpBridge<T>::s_streamCopyContainer;

				TlsCapableHttpBridge<network::TcpSocket>::TlsCapableHttpBridge(
					boost::asio::io_service* service,
					BaseInMemoryCertificateStore* certStore,
					boost::asio::ssl::context* defaultServerContext,
					boost::asio::ssl::context* clientContext,
					util::cb::HttpMessageBeginCheckFunction onMessageBegin,
					util::cb::HttpMessageEndCheckFunction onMessageEnd,
					util::cb::MessageFunction onInfoCb,
					util::cb::MessageFunction onWarnCb,
					util::cb::MessageFunction onErrorCb
					) :
					util::cb::EventReporter(
						onInfoCb, 
						onWarnCb, 
						onErrorCb
						),
					m_upstreamSocket(*service), 
					m_downstreamSocket(*service),
					m_upstreamStrand(*service),
					m_downstreamStrand(*service),
					m_resolver(*service),
					m_streamTimer(*service),
					m_certStore(certStore),
					m_onMessageBegin(onMessageBegin),
					m_onMessageEnd(onMessageEnd)
				{	

					// We purposely don't catch here. We want the acceptor to catch.
					m_request.reset(new http::HttpRequest());
					m_response.reset(new http::HttpResponse());
					
					// XXX TODO - This is ugly, our bad design is showing. See notes in the
					// EventReporter class header.
					m_request->SetOnInfo(m_onInfo);
					m_request->SetOnWarning(m_onWarning);
					m_request->SetOnError(m_onError);
					m_response->SetOnInfo(m_onInfo);
					m_response->SetOnWarning(m_onWarning);
					m_response->SetOnError(m_onError);
				}
				
				TlsCapableHttpBridge<network::TlsSocket>::TlsCapableHttpBridge(
					boost::asio::io_service* service,
					BaseInMemoryCertificateStore* certStore,
					boost::asio::ssl::context* defaultServerContext,
					boost::asio::ssl::context* clientContext,
					util::cb::HttpMessageBeginCheckFunction onMessageBegin,
					util::cb::HttpMessageEndCheckFunction onMessageEnd,
					util::cb::MessageFunction onInfoCb,
					util::cb::MessageFunction onWarnCb,
					util::cb::MessageFunction onErrorCb
					)
					:
					util::cb::EventReporter(
						onInfoCb,
						onWarnCb,
						onErrorCb
						),
					m_upstreamSocket(*service, *clientContext),
					m_downstreamSocket(*service, *defaultServerContext),
					m_upstreamStrand(*service),
					m_downstreamStrand(*service),
					m_resolver(*service),
					m_streamTimer(*service),
					m_certStore(certStore),
					m_onMessageBegin(onMessageBegin),
					m_onMessageEnd(onMessageEnd)
				{
					#ifndef NDEBUG
						assert(m_certStore != nullptr && u8"In TlsCapableHttpBridge<network::TlsSocket>::TlsCapableHttpBridge(... args) - Supplied certificate store is nullptr!");						
					#else
						if (m_certStore == nullptr)
						{
							throw std::runtime_error(u8"In TlsCapableHttpBridge<network::TlsSocket>::TlsCapableHttpBridge(... args) - Supplied certificate store is nullptr!");
						}
					#endif
					

					// We purposely don't catch here. We want the acceptor to catch
					// this.
					m_request.reset(new http::HttpRequest());
					m_response.reset(new http::HttpResponse());

					// Init TLS peek buffer.
					m_tlsPeekBuffer.reset(new std::array<char, TlsPeekBufferSize>());	

					// XXX TODO - This is ugly, our bad design is showing. See notes in the
					// EventReporter class header.
					m_request->SetOnInfo(m_onInfo);
					m_request->SetOnWarning(m_onWarning);
					m_request->SetOnError(m_onError);

					m_response->SetOnInfo(m_onInfo);
					m_response->SetOnWarning(m_onWarning);
					m_response->SetOnError(m_onError);

				}

				template<>
				void TlsCapableHttpBridge<network::TcpSocket>::Start()
				{
					try
					{
						SetStreamTimeout(boost::posix_time::minutes(5));
	
						TryInitiateHttpTransaction();
						return;
					}
					catch (std::exception& e)
					{
						std::string errMessage(u8"IN TlsCapableHttpBridge<network::TcpSocket>::Start() - Got error:\t");
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
						SetStreamTimeout(boost::posix_time::minutes(5));

						// Start a peek read on the connected secure client, so we can attempt to extract the
						// SNI hostname in the handler without screwing up the pending handshake.
						m_downstreamSocket.next_layer().async_receive(
							boost::asio::buffer(*m_tlsPeekBuffer.get(), m_tlsPeekBuffer->size()), 
							boost::asio::ip::tcp::socket::message_peek,
							m_downstreamStrand.wrap(
								std::bind(&TlsCapableHttpBridge::OnTlsPeek, 
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
						std::string errMessage(u8"IN TlsCapableHttpBridge<network::TlsSocket>::Start() - Got error:\t");
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

				template<class BridgeSocketType>
				const void TlsCapableHttpBridge<BridgeSocketType>::InitClientContext(TlsCapableHttpBridge<BridgeSocketType>* bridgeCtx, boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& sslStream, const std::string& hostname)
				{
					while (s_clientContextLock.test_and_set(std::memory_order_acquire))
					{
						cpu_relax();
					}

					auto existingCtx = s_clientContexts.find(hostname);
					if (existingCtx != s_clientContexts.end())
					{
						std::unique_ptr<boost::asio::ssl::context>& uPtr = existingCtx->second;
						
						SSL_set_SSL_CTX(sslStream.native_handle(), uPtr->native_handle());
					}
					else
					{
						std::unique_ptr<boost::asio::ssl::context> newContext;
						newContext.reset(new boost::asio::ssl::context(sslStream.get_io_service(), boost::asio::ssl::context::sslv23_client));

                        newContext->set_options(
                            boost::asio::ssl::context::no_compression |
                            boost::asio::ssl::context::default_workarounds |
                            boost::asio::ssl::context::no_sslv2 |
                            boost::asio::ssl::context::no_sslv3
                        );

						newContext->set_verify_mode(boost::asio::ssl::context::verify_peer | boost::asio::ssl::context::verify_fail_if_no_peer_cert);

						SSL_CTX_set_cipher_list(newContext->native_handle(), u8"HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4");

						SSL_CTX_set_ecdh_auto(newContext->native_handle(), 1);

                        if (X509_VERIFY_PARAM_set_flags(newContext->native_handle()->param, X509_V_FLAG_TRUSTED_FIRST) != 1)
                        {
                            // XXX TODO
                            // No context from which to call ReportX methods because we're a static function here.
                        }

						auto defaultContext = SSL_get_SSL_CTX(sslStream.native_handle());
						
						if (defaultContext != nullptr)
						{
							auto defaultCertStore = SSL_CTX_get_cert_store(defaultContext);

							if (defaultCertStore != nullptr)
							{
								SSL_CTX_set_cert_store(newContext->native_handle(), defaultCertStore);
							}
							else
							{
								bridgeCtx->ReportError(u8"In TlsCapableHttpBridge<BridgeSocketType>::InitClientContext(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>&, const std::string&) - Failed to get default certificate store.");
							}
						}
						else
						{
							bridgeCtx->ReportError(u8"In TlsCapableHttpBridge<BridgeSocketType>::InitClientContext(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>&, const std::string&) - Failed to get default client context.");
						}

						SSL_set_SSL_CTX(sslStream.native_handle(), newContext->native_handle());

						s_clientContexts.emplace(hostname, std::move(newContext));
					}

					s_clientContextLock.clear(std::memory_order_release);
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

					#ifndef NDEBUG
					ReportInfo(u8"TlsCapableHttpBridge<network::TcpSocket>::OnUpstreamConnect");
					#endif // !NDEBUG

					if (!error)
					{					
						if (m_request->IsPayloadComplete() == false && m_request->GetConsumeAllBeforeSending() == true)
						{
							// Means that there is a request payload, it's not complete, and it's been flagged
							// for inspection before being sent upstream. Another read from the client is
							// required.
							
							try
							{
								auto requestReadBuffer = m_request->GetReadBuffer();

								boost::asio::async_read(
									m_downstreamSocket,
									requestReadBuffer,
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
								std::string errMsg(u8"In TlsCapableHttpBridge<network::TlsSocket>::OnUpstreamConnect(const boost::system::error_code&) - Got error:\t");
								errMsg.append(e.what());
								ReportError(errMsg);
							}							
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
									std::placeholders::_1
									)
								)
							);

						return;
					}
					else
					{
						std::string errMsg(u8"In TlsCapableHttpBridge<network::TlsSocket>::OnUpstreamConnect(const boost::system::error_code&) - Got error:\t");
						errMsg.append(error.message());
						ReportError(errMsg);
					}
					
					Kill();
				}

				template<>
				void TlsCapableHttpBridge<network::TlsSocket>::OnUpstreamConnect(const boost::system::error_code& error)
				{

					#ifndef NDEBUG
					ReportInfo(u8"TlsCapableHttpBridge<network::TlsSocket>::OnUpstreamConnect");
					#endif // !NDEBUG

					if (!error)
					{						
						SetStreamTimeout(boost::posix_time::minutes(5));

						boost::system::error_code scerr;

						m_upstreamSocket.set_verify_callback(
							std::bind(
								&TlsCapableHttpBridge::VerifyServerCertificateCallback, 
								shared_from_this(),
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
										std::placeholders::_1
										)
									)
								);

							return;
						}
						else
						{
							std::string errMsg(u8"In TlsCapableHttpBridge<network::TlsSocket>::OnUpstreamConnect(const boost::system::error_code&) - While setting verification callback, got error:\t");
							errMsg.append(error.message());
							ReportError(errMsg);
						}
					}
					else
					{
						std::string errMsg(u8"In TlsCapableHttpBridge<network::TlsSocket>::OnUpstreamConnect(const boost::system::error_code&) - Got error:\t");
						errMsg.append(error.message());
						ReportError(errMsg);
					}

					Kill();
				}

				template<>
				void TlsCapableHttpBridge<network::TcpSocket>::OnResolve(const boost::system::error_code& error, boost::asio::ip::tcp::resolver::iterator endpointIterator)
				{

					#ifndef NDEBUG
					ReportInfo(u8"TlsCapableHttpBridge<network::TcpSocket>::OnResolve");
					#endif // !NDEBUG

					if (!error)
					{
						SetStreamTimeout(boost::posix_time::minutes(5));

						//auto ep = *endpointIterator;

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
						if (m_upstreamHostPort != 0)
						{
							auto epClone = endpointIterator;
							boost::asio::ip::tcp::resolver::iterator end;
							while (epClone != end)
							{
								epClone->endpoint().port(m_upstreamHostPort);
								++epClone;
							}							
						}

						// XXX TODO. The correct thing to do here is keep the iterator somehow, then in
						// the completion handler, in the event of a connection related error, keep
						// incrementing through the iterator until all possible endpoints for the
						// requested host have been exhausted. Doing things this way means that we
						// only take a crack at connecting to the first A record entry resolved, then
						// quit if that first record does not work.

						boost::asio::async_connect(
							m_upstreamSocket,
							endpointIterator,
							std::bind(
								&TlsCapableHttpBridge::OnUpstreamConnect,
								shared_from_this(),
								std::placeholders::_1
							));
						/*
						m_upstreamSocket.async_connect(
							ep, 
							m_upstreamStrand.wrap(
								std::bind(
									&TlsCapableHttpBridge::OnUpstreamConnect, 
									shared_from_this(), 
									std::placeholders::_1
									)
								)
							);
							*/
						return;
					}
					else
					{
						std::string errMsg(u8"In TlsCapableHttpBridge<network::TcpSocket>::OnResolve(const boost::system::error_code&, boost::asio::ip::tcp::resolver::iterator) - Got error:\t");
						errMsg.append(error.message());
						ReportError(errMsg);
					}

					Kill();
				}

				template<>
				void TlsCapableHttpBridge<network::TlsSocket>::OnResolve(const boost::system::error_code& error, boost::asio::ip::tcp::resolver::iterator endpointIterator)
				{	
					#ifndef NDEBUG
					ReportInfo(u8"TlsCapableHttpBridge<network::TlsSocket>::OnResolve");
					#endif // !NDEBUG

					if (!error)
					{
						// Set up our host specific client context.
						//InitClientContext(this, m_upstreamSocket, m_upstreamHost);

						SetStreamTimeout(boost::posix_time::minutes(5));

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

						if (m_upstreamHostPort != 0)
						{
							auto epClone = endpointIterator;
							boost::asio::ip::tcp::resolver::iterator end;
							while (epClone != end)
							{
								epClone->endpoint().port(m_upstreamHostPort);

								std::string epstr;
								epstr.append(epClone->endpoint().address().to_string());
								epstr.append(":");
								epstr.append(std::to_string(epClone->endpoint().port()));
								epstr.append(" hostname: ");
								epstr.append(epClone->host_name());
								epstr.append(" protocol: ");
								epstr.append(std::to_string(epClone->endpoint().protocol().family()));
								ReportInfo(epstr);

								++epClone;
							}
						}
						else
						{
							auto epClone = endpointIterator;
							boost::asio::ip::tcp::resolver::iterator end;
							while (epClone != end)
							{
								std::string epstr;
								epstr.append(epClone->endpoint().address().to_string());
								epstr.append(":");
								epstr.append(std::to_string(epClone->endpoint().port()));
								epstr.append(" hostname: ");
								epstr.append(epClone->host_name());
								epstr.append(" protocol: ");
								epstr.append(std::to_string(epClone->endpoint().protocol().family()));
								ReportInfo(epstr);
								++epClone;
							}
						}

						boost::asio::ip::tcp::endpoint requestedEndpoint = *endpointIterator;

						boost::asio::async_connect(
							m_upstreamSocket.lowest_layer(),
							endpointIterator,
							std::bind(
								&TlsCapableHttpBridge::OnUpstreamConnect,
								shared_from_this(),
								std::placeholders::_1
							));

						/*
						m_upstreamSocket.lowest_layer().async_connect(
							boost::asio::ip::tcp::endpoint(requestedEndpoint.address(), m_upstreamHostPort),
							m_upstreamStrand.wrap(
								std::bind(
									&TlsCapableHttpBridge::OnUpstreamConnect, 
									shared_from_this(), 
									std::placeholders::_1
									)
								)
							);
						*/
						return;
					}
					else
					{
						std::string errMsg(u8"In TlsCapableHttpBridge<network::TlsSocket>::OnResolve(const boost::system::error_code&, boost::asio::ip::tcp::resolver::iterator) - Got error:\t");
						errMsg.append(error.message());
						ReportError(errMsg);
					}

					Kill();
				}
				
				template<>
				bool TlsCapableHttpBridge<network::TcpSocket>::VerifyServerCertificateCallback(bool preverified, boost::asio::ssl::verify_context& ctx)
				{
					// Do nothing.
					return false;
				}

				template<>
				bool TlsCapableHttpBridge<network::TlsSocket>::VerifyServerCertificateCallback(const bool preverified, boost::asio::ssl::verify_context& ctx)
				{	

					#ifndef NDEBUG
					ReportInfo(u8"TlsCapableHttpBridge<network::TlsSocket>::VerifyServerCertificateCallback");
					#endif // !NDEBUG

					auto res = web::http::client::details::verify_cert_chain_platform_specific(ctx, m_upstreamHost);
					if (res)
					{
						X509* curCert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
						m_upstreamCert = curCert;
					}
					else
					{
						m_upstreamCert = nullptr;
					}

					return res;
				}

			} /* namespace secure */
		} /* namespace mitm */
	} /* namespace httpengine */
} /* namespace te */