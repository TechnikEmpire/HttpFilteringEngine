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

#include "../../network/SocketTypes.hpp"
#include <memory>

/// <summary>
/// Forward declarations separate, looks cleaner.
/// </summary>
namespace te
{
	namespace httpengine
	{
		namespace filtering
		{
			namespace http
			{

				class HttpFilteringEngine;

			} /* namespace http */
		} /* namespace filtering */

		namespace mitm
		{
			namespace http
			{

				class HttpRequest;
				class HttpResponse;

			} /* namespace http */
		} /* namespace mitm */
	} /* namespace httpengine */
}

namespace te
{
	namespace httpengine
	{
		namespace mitm
		{
			namespace secure
			{		

				/// <summary>
				/// Forward declaration of BaseInMemoryCertificateStore exists here because the
				/// namespace is the same.
				/// </summary>
				class BaseInMemoryCertificateStore;

				/// <summary>
				/// 
				/// </summary>
				template<class BridgeSocketType>
				class TlsCapableHttpBridge : std::enable_shared_from_this< TlsCapableHttpBridge<BridgeSocketType> >
				{

				/// <summary>
				/// Enforce use of this class to the only two types of sockets it is intended to be
				/// used with.
				/// </summary>
				static_assert(
					(std::is_same<BridgeSocketType, network::TcpSocket> ::value || std::is_same<BridgeSocketType, network::SslSocket>::value) &&
					u8"TlsCapableHttpBridge can only accept boost::asio::ip::tcp::socket or boost::asio::ssl::stream<boost::asio::ip::tcp::socket> as valid template parameters."
					);

				public:
					
					TlsCapableHttpBridge(
						boost::asio::io_service* service,
						BaseInMemoryCertificateStore* certStore,
						const HttpFilteringEngine* filteringEngine,
						boost::asio::ssl::context* defaultServerContext = nullptr,
						boost::asio::ssl::context* clientContext = nullptr
						);

					/// <summary>
					/// No copy no move no thx.
					/// </summary>
					TlsCapableHttpBridge(const TlsCapableHttpBridge&) = delete;
					TlsCapableHttpBridge(TlsCapableHttpBridge&&) = delete;
					TlsCapableHttpBridge& operator=(const TlsCapableHttpBridge&) = delete;

					~TlsCapableHttpBridge()
					{
						m_request.reset();
						m_response.reset();
					}

				private:

					/// <summary>
					/// HTTP request object which is read from the connected client and written to
					/// the upstream host.
					/// </summary>
					std::unique_ptr<HttpRequest> m_request = nullptr;

					/// <summary>
					/// HTTP response object which is read from the upstream host and written to the
					/// downstream client.
					/// </summary>
					std::unique_ptr<HttpResponse> m_response = nullptr;

					/// <summary>
					/// Every bridge requires a valid pointer to a filtering engine which may or may
					/// not be shared, for subjecting HTTP requests and responses to filtering.
					/// </summary>
					const HttpFilteringEngine* m_filteringEngine = nullptr;

					/// <summary>
					/// Socket used to connect to the client's desired host.
					/// </summary>
					BridgeSocketType m_upstreamSocket;

					/// <summary>
					/// Socket used for connecting to the client.
					/// </summary>
					BridgeSocketType m_downstreamSocket;

					/// <summary>
					/// Stores the current host whenever a new request is processed by the bridge.
					/// For every subsequent request, the host information in the request headers is
					/// compared to the host we presently have an upstream connection with. If the
					/// new request host does not match, the bridge is terminated.
					/// </summary>
					std::string m_upstreamHost;

					boost::asio::strand m_upstreamStrand;

					boost::asio::strand m_downstreamStrand;

					boost::asio::deadline_timer m_streamTimer;

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
					const boost::asio::ip::tcp::socket& DownstreamSocket() const;

					/// <summary>
					/// It's necessary for HTTP and HTTPS listeners to have access to the underlying
					/// TCP socket, for the purpose of accepting clients to initiate a new
					/// transaction. This method uses template specialization in the in the source,
					/// as accessing the correct layer varies between socket types.
					/// </summary>
					/// <returns>
					/// The underlying TCP socket.
					/// </returns>
					const boost::asio::ip::tcp::socket& UpstreamSocket() const;

					/// <summary>
					/// Initiates the process of reading and writing between client and server.
					/// After this call, the bridge maintains its own lifecycle via shared_from_this
					/// passed to async method handlers.
					/// </summary>
					void Start();

				private:

					void OnResolve(const boost::system::error_code& err, boost::asio::ip::tcp::resolver::iterator endpoint_iterator);

					void OnUpstreamConnect(const boost::system::error_code& error);

					void OnUpstreamHeaders(const boost::system::error_code& error, const size_t bytes_transferred)
					{
						SSL_CTX_set_tlsext_servername_callback()
					}

					void OnUpstreamRead(const boost::system::error_code& error, const size_t bytes_transferred)
					{

					}

					void OnUpstreamWrite(const boost::system::error_code& error)
					{

					}

					void OnDownstreamHeaders(const boost::system::error_code& error, const size_t bytes_transferred)
					{

					}

					void OnDownstreamRead(const boost::system::error_code& error, const size_t bytes_transferred)
					{

					}

					void OnDownstreamWrite(const boost::system::error_code& error)
					{

					}

					void OnStreamTimeout(const boost::system::error_code& e)
					{

					}

					void SetStreamTimeout(uint32_t millisecondsFromNow)
					{

					}

					void OnUpstreamHandshake(const boost::system::error_code& error)
					{

					}

					void OnDownstreamHandshake(const boost::system::error_code& error)
					{

					}

					static int OnTlsServerName(SSL* ssl, int* ad, void* arg)
					{						
						assert(ssl != nullptr && u8"In TlsCapableHttpBridge::OnTlsServerName(SSL*, int*, void*) - SSL context is nullptr!");

						if (!ssl)
						{
							return SSL_TLSEXT_ERR_NOACK;
						}

						BaseInMemoryCertificateStore* memCertStore = static_cast<BaseInMemoryCertificateStore*>(arg);
						
						assert(memCertStore != nullptr && u8"In TlsCapableHttpBridge::OnTlsServerName(SSL*, int*, void*) - BaseInMemoryCertificateStore* via void* arg param is nullptr!");

						if (!memCertStore)
						{
							return SSL_TLSEXT_ERR_NOACK;
						}

						const char* hostName = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

						if (!hostName || || servername[0] == '\0')
						{
							return SSL_TLSEXT_ERR_NOACK;
						}
												
						return SSL_TLSEXT_ERR_OK;
					}

					bool VerifyServerCertificateCallback(bool preverified, boost::asio::ssl::verify_context& ctx)
					{

					}

					void SetKeepAlive(SocketType& socket, const bool value);

					void SetLinger(SocketType& socket, const bool value);

					void SetNoDelay(SocketType& socket, const bool value);

				};

			} /* namespace secure */
		} /* namespace mitm */
	} /* namespace httpengine */
} /* namespace te */
