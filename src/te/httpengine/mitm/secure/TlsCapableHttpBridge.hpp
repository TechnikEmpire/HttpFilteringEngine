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
*    | Read downstream client    <-----+ Perform downstream     +^-+
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
*/

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

					std::unique_ptr<HttpRequest> m_request = nullptr;

					std::unique_ptr<HttpResponse> m_response = nullptr;

					const HttpFilteringEngine* m_filteringEngine = nullptr;

					BridgeSocketType m_upstreamSocket;

					SocketType m_downstreamSocket;

					boost::asio::strand m_upstreamStrand;

					boost::asio::strand m_downstreamStrand;

					boost::asio::deadline_timer m_streamTimer;

				public:

					const boost::asio::ip::tcp::socket& DownstreamSocket() const;

					const boost::asio::ip::tcp::socket& UpstreamSocket() const;

					void Start();

				private:

					void OnResolve(const boost::system::error_code& err, boost::asio::ip::tcp::resolver::iterator endpoint_iterator);

					void OnUpstreamConnect(const boost::system::error_code& error);

					void OnUpstreamHeaders(const boost::system::error_code& error, const size_t bytes_transferred)
					{

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
