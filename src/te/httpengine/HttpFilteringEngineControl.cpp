/*
* Copyright © 2017 Jesse Nicholson
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

#include "HttpFilteringEngineControl.hpp"
#include <functional>
#include <boost/predef.h>

// Because we're using ::asio inside a library, and it's a header only library,
// we need to include the source in one place alone, and that's here. We also
// need to add some preprocessor directives. This is all covered in the docs
// here: http://www.boost.org/doc/libs/1_60_0/doc/html/boost_asio/using.html#boost_asio.using.optional_separate_compilation
#include <boost/asio/impl/src.hpp>
#include <boost/asio/ssl/impl/src.hpp>

// On Windows, because of how WinSock requires manual startup/shutdown on a 
// per-process basis, boost::asio uses an atomic static reference counting
// system to transparently handle this tedious process. Since we're consuming
// boost::asio into a shared lib rather than a exe, this system does not 
// function correctly. This is the solution according to the docs, to manually
// force that static ref count to increment, which will cause it to never
// decrement below 1, and therefore will not call WSACleanup on us.
//
// As such, it's up to us to manually call WSAStartup/WSACleanup.
#include <boost/predef/os.h>
#include <boost/predef/compiler.h>

#if BOOST_OS_WINDOWS

	#include <boost/asio/detail/winsock_init.hpp>

	#ifdef _MSC_VER
		#pragma warning(push)
		#pragma warning(disable:4073)
		#pragma init_seg(lib)
	#endif

	boost::asio::detail::winsock_init<>::manual manual_winsock_init;

	#ifdef _MSC_VER
		#pragma warning(pop)
	#endif

	#include "mitm/secure/WindowsInMemoryCertificateStore.hpp"
#else
	#include "NO_PLATFORM_SPECIFIC_CERTIFICATE_STORE_FOUND.hpp"
#endif

#include "mitm/diversion/DiversionControl.hpp"

namespace te
{
	namespace httpengine
	{

		HttpFilteringEngineControl::HttpFilteringEngineControl(
			util::cb::FirewallCheckFunction firewallCb,
			std::string caBundleAbsolutePath,
			uint16_t httpListenerPort,
			uint16_t httpsListenerPort,
			uint32_t proxyNumThreads,
			util::cb::HttpMessageBeginCheckFunction onMessageBegin,
			util::cb::HttpMessageEndCheckFunction onMessageEnd,
			util::cb::MessageFunction onInfo,
			util::cb::MessageFunction onWarn,
			util::cb::MessageFunction onError
		)
			:
			util::cb::EventReporter(onInfo, onWarn, onError),
			m_firewallCheckCb(firewallCb),
			m_caBundleAbsolutePath(caBundleAbsolutePath),
			m_httpListenerPort(httpListenerPort),
			m_httpsListenerPort(httpsListenerPort),
			m_proxyNumThreads(proxyNumThreads),
			m_isRunning(false),
			m_onMessageBegin(onMessageBegin),
			m_onMessageEnd(onMessageEnd)
		{
			if (m_store == nullptr)
			{
				// XXX TODO - Make a factory for cert store so we don't have this horrible mess everywhere.
				#if BOOST_OS_WINDOWS
					m_store.reset(new mitm::secure::WindowsInMemoryCertificateStore(u8"CA", u8"Http Filtering Engine", u8"Http Filtering Engine"));
				#elif BOOST_OS_ANDROID
					You poor guy.You didn't write a cert store for Android. Are you new?
				#else
					You poor guy.You didn't write a cert store for this OS. Are you new ?
				#endif

				if (!m_store->EstablishOsTrust())
				{
					throw std::runtime_error(u8"In HttpFilteringEngineControl::Start() - Failed to establish certificate trust with OS.");
				}
			}

			if (!m_onMessageBegin)
			{
				m_onMessageBegin = std::bind(&HttpFilteringEngineControl::DummyOnMessageBeginCallback, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6, std::placeholders::_7, std::placeholders::_8, std::placeholders::_9, std::placeholders::_10);
			}

			if (!m_onMessageEnd)
			{
				m_onMessageEnd = std::bind(&HttpFilteringEngineControl::DummyOnMessageEndCallback, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, std::placeholders::_6, std::placeholders::_7, std::placeholders::_8, std::placeholders::_9, std::placeholders::_10);
			}
		}

		HttpFilteringEngineControl::~HttpFilteringEngineControl()
		{
			// Cleanup any installed certs HERE.
			if (m_store != nullptr)
			{
				try
				{
					m_store->RevokeOsTrust();
				}
				catch (std::runtime_error& e)
				{
					// XXX TODO What can we really do here?
				}				
			}
		}

		void HttpFilteringEngineControl::Start()
		{
			std::lock_guard<std::mutex> lock(m_ctlMutex);

			if (m_isRunning == false)
			{
				if (m_service == nullptr)
				{
					m_service.reset(new boost::asio::io_service());
				}
				else					
				{					
					m_service->reset();
				}				

				m_httpAcceptor.reset(
					new mitm::secure::TcpAcceptor(
						m_service.get(),
						m_httpListenerPort,
						m_caBundleAbsolutePath,
						nullptr,
						m_onMessageBegin,
						m_onMessageEnd,
						m_onInfo,
						m_onWarning,
						m_onError
						)
					);

				#ifdef NDEBUG
					assert(m_store != nullptr && "In HttpFilteringEngineControl::Start() - Cert store is nullptr!");
				#endif

				m_httpsAcceptor.reset(
					new mitm::secure::TlsAcceptor(
						m_service.get(),
						m_httpsListenerPort,
						m_caBundleAbsolutePath,
						m_store.get(),
						m_onMessageBegin,
						m_onMessageEnd,
						m_onInfo,
						m_onWarning,
						m_onError
						)
					);

				m_httpAcceptor->AcceptConnections();

				m_httpsAcceptor->AcceptConnections();

				m_diversionControl.reset(new mitm::diversion::DiversionControl(m_firewallCheckCb, m_onInfo, m_onWarning, m_onError));

				m_diversionControl->SetHttpListenerPort(m_httpAcceptor->GetListenerPort());

				m_diversionControl->SetHttpsListenerPort(m_httpsAcceptor->GetListenerPort());

				m_diversionControl->Run();

				for (uint32_t i = 0; i < m_proxyNumThreads; ++i)
				{
					m_proxyServiceThreads.emplace_back(
						std::thread
							{ 
								std::bind(
								static_cast<size_t(boost::asio::io_service::*)()>(&boost::asio::io_service::run), 
									std::ref(*m_service.get())
									) 
							}
					);
				}

				m_isRunning = true;
			}			
		}

		void HttpFilteringEngineControl::Stop()
		{
			std::lock_guard<std::mutex> lock(m_ctlMutex);
			
			if (m_isRunning == true)
			{				
				m_httpAcceptor->StopAccepting();
				m_httpsAcceptor->StopAccepting();
				m_diversionControl->Stop();
				m_service->stop();

				for (auto& t : m_proxyServiceThreads)
				{
					t.join();
				}

				m_proxyServiceThreads.clear();

				m_isRunning = false;
			}
		}

		bool HttpFilteringEngineControl::IsRunning() const
		{
			return m_isRunning;
		}

		const uint32_t HttpFilteringEngineControl::GetHttpListenerPort() const
		{
			if (m_isRunning && m_httpAcceptor != nullptr)
			{
				return m_httpAcceptor->GetListenerPort();
			}

			return 0;
		}

		const uint32_t HttpFilteringEngineControl::GetHttpsListenerPort() const
		{
			if (m_isRunning && m_httpsAcceptor != nullptr)
			{
				return m_httpsAcceptor->GetListenerPort();
			}

			return 0;
		}

		std::vector<char> HttpFilteringEngineControl::GetRootCertificatePEM() const
		{
			if (m_store)
			{
				return m_store->GetRootCertificatePEM();
			}

			return{};
		}

		void HttpFilteringEngineControl::DummyOnMessageBeginCallback(
			const char* requestHeaders, const uint32_t requestHeadersLength, const char* requestBody, const uint32_t requestBodyLength,
			const char* responseHeaders, const uint32_t responseHeadersLength, const char* responseBody, const uint32_t responseBodyLength,
			uint32_t* nextAction, CustomResponseStreamWriter responseWriter
		)
		{
			// Do nothing, say nothing, tell no one.
		}

		void HttpFilteringEngineControl::DummyOnMessageEndCallback(
			const char* requestHeaders, const uint32_t requestHeadersLength, const char* requestBody, const uint32_t requestBodyLength,
			const char* responseHeaders, const uint32_t responseHeadersLength, const char* responseBody, const uint32_t responseBodyLength,
			bool* shouldBlock, CustomResponseStreamWriter responseWriter
		)
		{
			// Do nothing, say nothing, tell no one.
		}

	} /* namespace httpengine */
} /* namespace te */
