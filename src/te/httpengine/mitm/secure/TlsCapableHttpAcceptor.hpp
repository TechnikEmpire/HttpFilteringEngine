/*
* Copyright © 2017 Jesse Nicholson
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

#pragma once

#include "TlsCapableHttpBridge.hpp"
#include "../../util/cb/EventReporter.hpp"

#include <boost/asio.hpp>
#include <type_traits>
#include <memory>
#include <stdexcept>

namespace te
{
	namespace httpengine
	{
		namespace mitm
		{
			namespace secure
			{
				class BaseInMemoryCertificateStore;
			} /* namespace secure */
		} /* namespace mitm */

		namespace filtering
		{		
			namespace http
			{
				class HttpFilteringEngine;
			} /* namespace http */
		} /* namespace filtering */
	} /* namespace httpengine */
} /* namespace te */

namespace te
{
	namespace httpengine
	{
		namespace mitm
		{
			namespace secure
			{

				/// <summary>
				/// The TlsCapableHttpAcceptor handles accepting both plain TCP and TLS clients. The
				/// functionality is customized simply by modifying the template parameter. Valid
				/// parameters are network::TcpSocket and network::TlsSocket.
				/// 
				/// In the event that AcceptorType is network::TlsSocket, some of the optional
				/// parameters become required, such as the in memory certificate store,
				/// </summary>
				template<class AcceptorType>
				class TlsCapableHttpAcceptor : public util::cb::EventReporter
				{

					/// <summary>
					/// Enforce use of this class to the only two types of sockets it is intended to be
					/// used with.
					/// </summary>
					static_assert((std::is_same<AcceptorType, network::TcpSocket> ::value || std::is_same<AcceptorType, network::TlsSocket>::value), "TlsCapableHttpAcceptor can only accept boost::asio::ip::tcp::socket or boost::asio::ssl::stream<boost::asio::ip::tcp::socket> as valid template parameters.");

				private:

					using SharedBridge = std::shared_ptr< TlsCapableHttpBridge<AcceptorType> >;

				public:

					/// <summary>
					/// Constructs a new TlsCapableHttpAcceptor. In the event that AcceptorType is
					/// network::TlsSocket, some of the optional parameters become required, such as
					/// the in memory certificate store. This constructor should be expected to throw
					/// std::runtime_error in the event that context-invalid parameters are supplied.
					/// </summary>
					/// <param name="service">
					/// A valid pointer to the ::asio::io_service that will be driving the acceptor.
					/// </param>
					/// <param name="filteringEngine">
					/// A valid pointer to the HttpFilteringEngine that will be provided to each
					/// client, and used to filter client requests and data according to configured
					/// options.
					/// </param>
					/// <param name="port">
					/// The port number that the acceptor should listen on. Default value is zero,
					/// which tells the OS to select an available port from the ephimeral port
					/// range. It is recommended that the default value of zero be used. The
					/// ::GetListenerPort() member can be used post-construction to find out which
					/// port was selected.
					/// </param>
					/// <param name="caBundleAbsPath">
					/// An optional absolute path to a CA bundle that the default client context can
					/// use for upstream certificate verification. Default value is "none." If the
					/// parameter is left at its default value, no specific CA bundle will be
					/// loaded. Note however that ::set_default_verify_paths() will be called on the
					/// client context. This cannot be relied upon, as it's configuration and
					/// platform dependent.
					/// 
					/// This parameter is only used when AcceptorType is network::TlsSocket.
					/// </param>
					/// <param name="store">
					/// A valid pointer to the in memory certificate store that is to be used for
					/// spoofing and storing verified upstream certificates and corresponding server
					/// contexts. This store is supplied to every Tls client bridge for the purpose
					/// of serving secured clients.
					/// 
					/// This parameter is only required when AcceptorType is network::TlsSocket.
					/// </param>
					/// <param name="onInfoCb">
					/// An optional callback for general information about non-critical events.
					/// </param>
					/// <param name="onWarningCb">
					/// An optional callback for warnings about potentially critical events.
					/// </param>
					/// <param name="onErrorCb">
					/// An optional callback for error information about critical events that were
					/// handled.
					/// </param>
					TlsCapableHttpAcceptor(
						boost::asio::io_service* service,
						filtering::http::HttpFilteringEngine* filteringEngine,
						uint16_t port = 0,
						const std::string& caBundleAbsPath = std::string(u8"none"),
						BaseInMemoryCertificateStore* store = nullptr,
						util::cb::MessageFunction onInfoCb = nullptr,
						util::cb::MessageFunction onWarnCb = nullptr,
						util::cb::MessageFunction onErrorCb = nullptr
						) 
						:
						util::cb::EventReporter(onInfoCb, onWarnCb, onErrorCb),
						m_service(service),
						m_engine(filteringEngine),
						m_caBundleAbsolutePath(caBundleAbsPath),
						m_store(store),
						m_acceptor(*service, boost::asio::ip::tcp::endpoint(boost::asio::ip::address(), port)),
						m_clientContext(*service, boost::asio::ssl::context::sslv23_client),
						m_defaultServerContext(*service, boost::asio::ssl::context::tlsv12_server)
					{

						bool isTls = std::is_same<AcceptorType, network::TlsSocket>::value;
						#ifndef NDEBUG
							assert((isTls == (m_store != nullptr)) &&
								u8"In TlsCapableHttpAcceptor::TlsCapableHttpAcceptor(...) - Either type is TlsAcceptor and \
								supplied certificate store is nullptr, or type is TcpListener and a certificate store was supplied. \
								Certificate stores are required only for TlsAcceptor types.");
						#else
							if (isTls && m_store == nullptr)
							{
								throw std::runtime_error(u8"In TlsCapableHttpAcceptor::TlsCapableHttpAcceptor(...) - Supplied cert store is nullptr!");
							}

							if(!isTls && m_store != nullptr)
							{
								ReportWarning(u8"In TlsCapableHttpAcceptor::TlsCapableHttpAcceptor(...) - Cert was supplied to non TLS acceptor.");
							}
						#endif

						boost::system::error_code reuseAddrEc;
						m_acceptor.set_option(boost::asio::socket_base::reuse_address(true), reuseAddrEc);

						if (reuseAddrEc)
						{
							std::string errMessage(u8"In TlsCapableHttpAcceptor::StopAccepting(const boost::system::error_code&) - Got error:\t");
							errMessage.append(reuseAddrEc.message());
							ReportError(errMessage);
						}

						if (std::is_same<AcceptorType, network::TlsSocket>::value)
						{
							if (m_store == nullptr)
							{
								throw std::runtime_error(u8"In TlsCapableHttpAcceptor::TlsCapableHttpAcceptor(...) - Supplied cert store is nullptr!");
							}

							InitContexts();
						}
					}					

					/// <summary>
					/// No copy no move no thx.
					/// </summary>
					TlsCapableHttpAcceptor(const TlsCapableHttpAcceptor&) = delete;
					TlsCapableHttpAcceptor(TlsCapableHttpAcceptor&&) = delete;
					TlsCapableHttpAcceptor& operator=(const TlsCapableHttpAcceptor&) = delete;

					/// <summary>
					/// Default destructor.
					/// </summary>
					~TlsCapableHttpAcceptor()
					{

					}

					/// <summary>
					/// Gets the port on which the acceptor is accepting new client connections.
					/// </summary>
					/// <returns>
					/// The port on which the acceptor is accepting new client connections.
					/// </returns>
					const uint16_t GetListenerPort() const
					{
						return m_acceptor.local_endpoint().port();
					}

					/// <summary>
					/// Initiates the process of accepting a new client asynchronously.
					/// </summary>
					/// <returns>
					/// True if the async_accept was initiated without error, false otherwise.
					/// </returns>
					const bool AcceptConnections()
					{
						if (m_service != nullptr)
						{
							try
							{
								SharedBridge session = std::make_shared<TlsCapableHttpBridge<AcceptorType>>(m_service, m_engine, m_store, &m_defaultServerContext, &m_clientContext, m_onInfo, m_onWarning, m_onError);

								if (session == nullptr)
								{
									ReportError(u8"In TlsCapableHttpAcceptor::HandleAccept(const boost::system::error_code&) - Failed to allocate new session!");
									return false;
								}

								m_acceptor.async_accept(session->DownstreamSocket(), std::bind(&TlsCapableHttpAcceptor::HandleAccept, this, std::placeholders::_1, session));
								return true;
							}
							catch (std::exception& e)
							{
								std::string errMessage(u8"In TlsCapableHttpAcceptor::HandleAccept(const boost::system::error_code&) - Got error:\t");
								errMessage.append(e.what());
								ReportError(errMessage);
							}
						}

						return false;
					}

					/// <summary>
					/// Cancels any pending async_accept calls, breaking the accept loop and thus
					/// stopping the acceptor from accepting any new client connections.
					/// </summary>
					void StopAccepting()
					{
						boost::system::error_code e;
						m_acceptor.cancel(e);

						if (e)
						{
							std::string errMessage(u8"In TlsCapableHttpAcceptor::StopAccepting(const boost::system::error_code&) - Got error:\t");
							errMessage.append(e.message());
							ReportError(errMessage);
						}
					}

				private:

					/// <summary>
					/// Initializes the default server and the client contexts, which are to be used
					/// in every single Tls client bridge. Only ever called when AcceptorType is
					/// network::TlsSocket.
					/// </summary>
					void InitContexts()
					{
						m_clientContext.set_options(
							boost::asio::ssl::context::no_compression | 
							boost::asio::ssl::context::default_workarounds | 
							boost::asio::ssl::context::no_sslv2 | 
							boost::asio::ssl::context::no_sslv3
							);

						m_defaultServerContext.set_options(
							boost::asio::ssl::context::no_compression |
							boost::asio::ssl::context::default_workarounds |
							boost::asio::ssl::context::no_sslv2 |
							boost::asio::ssl::context::no_sslv3
							);

						m_defaultServerContext.set_default_verify_paths();
						m_clientContext.set_default_verify_paths();

						if (m_caBundleAbsolutePath.compare(u8"none") != 0)
						{
							ReportInfo(u8"User specified an absolute path to ca-bundle for the client context. Attempting to load...");
							
							boost::system::error_code loadRootsError;							

							m_clientContext.load_verify_file(m_caBundleAbsolutePath, loadRootsError);

							if (loadRootsError)
							{
								// XXX TODO - Should we throw or something here? I think maybe not, since failing to load
								// the ca-bundle doesn't really hurt anything, just if the default verify paths are not
								// configured, client will get errors trying to browse secured stuff.
								std::string errMessage(u8"In TlsCapableHttpAcceptor::InitContexts() - While loading ca-bundle verification file, got error:\t");
								errMessage.append(loadRootsError.message());
								ReportError(errMessage);
							}
							else
							{
								ReportInfo(u8"Successfully loaded user-specified ca-bundle for client context certificate verification.");
							}
						}

						if (SSL_CTX_set_cipher_list(m_clientContext.native_handle(), BaseInMemoryCertificateStore::ContextCipherList.c_str()) != 1)
						{
							ReportWarning(u8"In TlsCapableHttpAcceptor::InitContexts() - Failed to cet client context cipher list.");
						}

						if (X509_VERIFY_PARAM_set_flags(m_clientContext.native_handle()->param, X509_V_FLAG_TRUSTED_FIRST) != 1)
						{
							ReportWarning(u8"In TlsCapableHttpAcceptor::InitContexts() - Failed to set X509_V_FLAG_TRUSTED_FIRST flag on client context. \
								This may cause some valid certificates to fail verification, because a cert found in their chain is unreachable and without this \
								option, verification must span the entire chain.");
						}
					}

					/// <summary>
					/// Completion handler for the acceptor async_accept calls. Attempts to initate
					/// the bridge transactions for the newly connected client, then moves to begin
					/// a new async_accept.
					/// </summary>
					/// <param name="error">
					/// Error code that will indicate if any errors were handled during the async
					/// operation, providing details if an error did occur and was handled.
					/// </param>
					/// <param name="session">
					/// The session constructed that should contain the newly accept client socket
					/// or ssl_stream.
					/// </param>
					void HandleAccept(const boost::system::error_code& error, SharedBridge session)
					{
						if (!error && session.get() != nullptr)
						{
							session->Start();

							if (!AcceptConnections())
							{
								ReportError(u8"In TlsCapableHttpAcceptor::HandleAccept(const boost::system::error_code&) - Failed to reinitiate accept.");
							}
						}
						else
						{
							if (error)
							{
								std::string errMessage(u8"In TlsCapableHttpAcceptor::HandleAccept(const boost::system::error_code&) - Got error:\t");
								errMessage.append(error.message());
							}
							else
							{
								ReportError(u8"In TlsCapableHttpAcceptor::HandleAccept(const boost::system::error_code&) - session is nullptr!");
							}
						}
					}

					/// <summary>
					/// Pointer to the io_service driving the acceptor.
					/// </summary>
					boost::asio::io_service* m_service = nullptr;
					
					/// <summary>
					/// Pointer to the HttpFilteringEngine that is to be supplied to each client
					/// bridge.
					/// </summary>
					filtering::http::HttpFilteringEngine* m_engine = nullptr;
					
					/// <summary>
					/// Absolute path to a CA bundle to be loaded by the client context, in the
					/// event that AcceptorType is network::TlsSocket. Default constructed with a
					/// value of "none". When contexts are being initialized, if the user has
					/// provided a path, this will have been constructed to that value, and the
					/// contained string will be supplied to OpenSSL in an attempt to load the file
					/// at the given path as the verification CA bundle for the client context.
					/// </summary>
					std::string m_caBundleAbsolutePath;

					/// <summary>
					/// Pointer to the certificate store to be supplied to each Tls client bridge.
					/// Of course this is only used when AcceptorType is network::TlsSocket. In the
					/// case that AcceptorType is network::TlsSocket, this parameter is mandator.
					/// </summary>
					BaseInMemoryCertificateStore* m_store = nullptr;

					/// <summary>
					/// The underlying TCP acceptor itself.
					/// </summary>
					boost::asio::ip::tcp::acceptor m_acceptor;

					/// <summary>
					/// The client context for each Tls client bridge. Only used when AcceptorType
					/// is network::TlsSocket.
					/// </summary>
					boost::asio::ssl::context m_clientContext;

					/// <summary>
					/// The default server context for each Tls client bridge. Only used when
					/// AcceptorType is network::TlsSocket. This context isn't ever actually used
					/// for anything, except to construct a ::asio::ssl_stream object within Tls
					/// client bridges.
					/// </summary>
					boost::asio::ssl::context m_defaultServerContext;				

				};

				using TcpAcceptor = TlsCapableHttpAcceptor<network::TcpSocket>;
				using TlsAcceptor = TlsCapableHttpAcceptor<network::TlsSocket>;

			} /* namespace secure */
		} /* namespace mitm */
	} /* namespace httpengine */
} /* namespace te */