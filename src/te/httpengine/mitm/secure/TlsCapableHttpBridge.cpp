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
					BaseInMemoryCertificateStore* certStore,
					const filtering::http::HttpFilteringEngine* filteringEngine,
					boost::asio::ssl::context* defaultServerContext,
					boost::asio::ssl::context* clientContext
					) : 
					m_upstreamSocket(*service), 
					m_downstreamSocket(*service),
					m_upstreamStrand(*service),
					m_downstreamStrand(*service),
					m_resolver(*service),
					m_streamTimer(*service),					
					m_certStore(certStore), 
					m_filteringEngine(filteringEngine)
				{
					m_request.reset(new http::HttpRequest());
					m_response.reset(new http::HttpResponse());
				}
				
				TlsCapableHttpBridge<network::SslSocket>::TlsCapableHttpBridge(
					boost::asio::io_service* service,
					BaseInMemoryCertificateStore* certStore,
					const filtering::http::HttpFilteringEngine* filteringEngine,
					boost::asio::ssl::context* defaultServerContext,
					boost::asio::ssl::context* clientContext
					)
					:
					m_upstreamSocket(*service, *clientContext),
					m_downstreamSocket(*service, *defaultServerContext),
					m_upstreamStrand(*service),
					m_downstreamStrand(*service),
					m_resolver(*service),
					m_streamTimer(*service),
					m_certStore(certStore),
					m_filteringEngine(filteringEngine)
				{
					m_request.reset(new http::HttpRequest());
					m_response.reset(new http::HttpResponse());
				}

				TlsCapableHttpBridge<network::TcpSocket>::~TlsCapableHttpBridge()
				{

				}

				TlsCapableHttpBridge<network::SslSocket>::~TlsCapableHttpBridge()
				{

				}

				template<>
				int TlsCapableHttpBridge<network::TcpSocket>::OnTlsServerName(SSL* ssl, int* ad, void* arg)
				{
					// Not implemented, should not be used.
				}

				template<>
				int TlsCapableHttpBridge<network::SslSocket>::OnTlsServerName(SSL* ssl, int* ad, void* arg)
				{

					// Something worth mentioning. This callback is invoked in the middle of the 
					// handshake with the client, to give the server the opportunity to fetch
					// the correct certificate. In our context, we've initiated the handshake 
					// with boost::asio using the async_handshake method, which took a copy of
					// TlsCapableHttpBridge<T>::shared_from_this(). At this point in execution,
					// that copy is still being held, so the life of the bridge we're using
					// here is being preserved by this.

					assert(ssl != nullptr && u8"In TlsCapableHttpBridge::OnTlsServerName(SSL*, int*, void*) - SSL context is nullptr!");

					if (!ssl)
					{
						return SSL_TLSEXT_ERR_ALERT_FATAL;
					}

					// A ptr to the bridge should always be the argument assigned for this callback, using
					// SSL_CTX_set_tlsext_servername_arg(...).
					TlsCapableHttpBridge<network::SslSocket>* bridge = static_cast<TlsCapableHttpBridge<network::SslSocket>*>(arg);

					assert(bridge != nullptr && u8"In TlsCapableHttpBridge::OnTlsServerName(SSL*, int*, void*) - TlsCapableHttpBridge<network::SslSocket>* via void* arg param is nullptr!");
					assert(bridge->m_certStore != nullptr && u8"In TlsCapableHttpBridge::OnTlsServerName(SSL*, int*, void*) - TlsCapableHttpBridge<network::SslSocket>*::m_certStore member is nullptr!");

					if (bridge == nullptr || bridge->m_certStore == nullptr)
					{
						return SSL_TLSEXT_ERR_ALERT_FATAL;
					}

					const char* hostName = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

					// Ensure hostname is valid befor attempting to go any further.
					if (!hostName || hostName[0] == '\0')
					{
						return SSL_TLSEXT_ERR_NOACK;
					}
										
					auto* serverContext = bridge->m_certStore->GetServerContext(hostName);

					if (serverContext == nullptr)
					{
						// No existing context for the specified host could be found. Now we need to go
						// fetch the real cert from the real host, and ask the store to spoof it and give
						// us a server context for this host.

						// Since we're in a static context here, let's use the socket(s) and resolver(s) we already
						// have in the supplied bridge object to fetch the upstream cert and spoof it.
						auto* upstreamSocket = &bridge->m_upstreamSocket;
						auto* resolver = &bridge->m_resolver;
						auto* upstreamStrand = &bridge->m_upstreamStrand;
						auto* timer = &bridge->m_streamTimer;

						assert(upstreamSocket != nullptr && u8"In TlsCapableHttpBridge::OnTlsServerName(SSL*, int*, void*) - TlsCapableHttpBridge<network::SslSocket>*::m_upstreamSocket member is nullptr!");
						assert(resolver != nullptr && u8"In TlsCapableHttpBridge::OnTlsServerName(SSL*, int*, void*) - TlsCapableHttpBridge<network::SslSocket>*::m_resolver member is nullptr!");
						assert(upstreamStrand != nullptr && u8"In TlsCapableHttpBridge::OnTlsServerName(SSL*, int*, void*) - TlsCapableHttpBridge<network::SslSocket>*::m_upstreamStrand member is nullptr!");

						bool resolved = false;
						boost::asio::ip::tcp::endpoint remoteHostEndpoint;
						
						if (resolver != nullptr && upstreamSocket != nullptr)
						{
							std::string requestedHost(hostName);
							boost::asio::ip::tcp::resolver::query query(requestedHost, "https");
							resolver->async_resolve(query, upstreamStrand->wrap(
								[&remoteHostEndpoint, &resolved](const boost::system::error_code& err, boost::asio::ip::tcp::resolver::iterator endpoint_iterator)
								{
									if (!err)
									{
										remoteHostEndpoint = *endpoint_iterator;
										resolved = true;
									}									
								}
							));

							// Let's give the resolver 3 seconds to give us an endpoint to connect to.
							boost::asio::deadline_timer timer(resolver->get_io_service());
							timer.expires_from_now(boost::posix_time::seconds(3));
							timer.wait();

							bool connected = false;
							bool verified = false;							
							bool didhandshake = false;
							X509* cert = nullptr;

							auto verificationCallback = 
								[&verified, &cert, &requestedHost] (bool preverified, boost::asio::ssl::verify_context& ctx)->bool
							{							
								boost::asio::ssl::rfc2818_verification v(requestedHost);
								verified = v(preverified, ctx);

								X509* curCert = X509_STORE_CTX_get_current_cert(ctx.native_handle());

								if (verified)
								{
									cert = curCert;
								}

								return verified;
							};

							auto onHandshake = 
								[&didhandshake](const boost::system::error_code& err)
							{
								// All we care about finding out is whether or not the async op actually
								// completed, so we know if we have to cancel it or not. We don't care if
								// an error was set, just that it completed at all.
								didhandshake = true;
							};

							if (resolved)
							{
								// Important! We have to tell our connecting socket which host it's connecting
								// for, so that SNI can function correctly in case the remote host defines more
								// than one hostname (which it most likely does).
								SSL_set_tlsext_host_name(upstreamSocket->native_handle(), hostName);
								
								upstreamSocket->lowest_layer().async_connect(remoteHostEndpoint, upstreamStrand->wrap(
									[&connected, &upstreamSocket, &upstreamStrand, onHandshake, verificationCallback](const boost::system::error_code& err)
									{
										if (!err)
										{
											// Handshake, supply our lambda callback for verification to get
											// the verified cert.
											boost::system::error_code scerr;
											upstreamSocket->set_verify_callback(verificationCallback, scerr);

											upstreamSocket->async_handshake(network::SslSocket::client, upstreamStrand->wrap(onHandshake));
										}										
									}
								));

								// Give the upstream socket 5 seconds to connect and handshake.
								timer.expires_from_now(boost::posix_time::seconds(5));
								timer.wait();

								if (connected && didhandshake && verified && cert != nullptr)
								{
									try
									{
										serverContext = bridge->m_certStore->SpoofCertificate(requestedHost, cert);
									}
									catch (std::runtime_error& e)
									{
										// XXX TODO - Report error through the bridge callbacks.
									}									
								}
								else
								{
									// In case one of these async calls is hung forever in the eternal void, cancel
									// here and bring it back before we return to the bridge from whence they came.
									if (!connected || !didhandshake)
									{
										upstreamSocket->lowest_layer().cancel();
									}									
								}
							}
							else
							{
								resolver->cancel();
							}
						}
					}

					if (serverContext != nullptr)
					{
						if (SSL_set_SSL_CTX(bridge->m_downstreamSocket.native_handle(), serverContext->native_handle()) == serverContext->native_handle())
						{
							return SSL_TLSEXT_ERR_OK;
						}
					}					

					return SSL_TLSEXT_ERR_ALERT_FATAL;
				}

			} /* namespace secure */
		} /* namespace mitm */
	} /* namespace httpengine */
} /* namespace te */