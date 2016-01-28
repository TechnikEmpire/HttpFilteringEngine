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

#include "HttpFilteringEngineControl.hpp"

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

#include "filtering/http/HttpFilteringEngine.hpp"
#include "mitm/diversion/DiversionControl.hpp"
#include "filtering/options/ProgramWideOptions.hpp"

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
			util::cb::MessageFunction onInfo,
			util::cb::MessageFunction onWarn,
			util::cb::MessageFunction onError,
			util::cb::RequestBlockFunction onRequestBlocked,
			util::cb::ElementBlockFunction onElementsBlocked
			)
			:
			util::cb::EventReporter(onInfo, onWarn, onError),			
			m_firewallCheckCb(firewallCb),
			m_onRequestBlockedCb(onRequestBlocked),
			m_onElementsBlockedCb(onElementsBlocked),
			m_caBundleAbsolutePath(caBundleAbsolutePath),
			m_httpListenerPort(httpListenerPort),
			m_httpsListenerPort(httpsListenerPort),
			m_proxyNumThreads(proxyNumThreads),
			m_programWideOptions(new filtering::options::ProgramWideOptions()),
			m_httpFilteringEngine(new filtering::http::HttpFilteringEngine(m_programWideOptions.get(), m_onRequestBlockedCb, m_onElementsBlockedCb)),
			m_isRunning(false)
		{
			
		}

		HttpFilteringEngineControl::~HttpFilteringEngineControl()
		{

		}

		void HttpFilteringEngineControl::Start()
		{
			std::unique_lock<std::mutex> lock(m_ctlMutex);

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

				if (m_store == nullptr)
				{
					// XXX TODO - Make a factory for cert store so we don't have this horrible mess everywhere.
					#if BOOST_OS_WINDOWS
						m_store.reset(new mitm::secure::WindowsInMemoryCertificateStore(u8"CA", u8"Http Filtering Engine", u8"Http Filtering Engine"));
					#elif BOOST_OS_ANDROID
						You poor guy. You didn't write a cert store for Android, and you didn't use a factory. Are you new?
					#else
						You poor guy.You didn't write a cert store for this OS, and you didn't use a factory. Are you new ?
					#endif

					if (!m_store->EstablishOsTrust())
					{
						throw new std::runtime_error(u8"In HttpFilteringEngineControl::Start() - Failed to establish certificate trust with OS.");
					}
				}

				// We purposely don't try/catch here, to allow callers to do this. From this class, we're at
				// the top of the chain. Caller is the big boss, let them take care here.

				if (m_httpAcceptor == nullptr)
				{
					m_httpAcceptor.reset(
						new mitm::secure::TcpAcceptor(
							m_service.get(), 
							m_httpFilteringEngine.get(), 
							m_httpListenerPort
							)
						);
				}

				if (m_httpsAcceptor == nullptr)
				{
					m_httpsAcceptor.reset(
						new mitm::secure::TlsAcceptor(
							m_service.get(), 
							m_httpFilteringEngine.get(), 
							m_httpsListenerPort, 
							m_caBundleAbsolutePath,
							m_store.get(), 
							m_onInfo, 
							m_onWarning, 
							m_onError
							)
						);
				}				

				m_httpAcceptor->AcceptConnections();

				m_httpsAcceptor->AcceptConnections();

				if (m_diversionControl == nullptr)
				{
					m_diversionControl.reset(new mitm::diversion::DiversionControl(m_firewallCheckCb, m_onInfo, m_onWarning, m_onError));
				}

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
			std::unique_lock<std::mutex> lock(m_ctlMutex);
			
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

		void HttpFilteringEngineControl::SetOptionEnabled(const uint32_t option, const bool enabled)
		{
			if (m_programWideOptions != nullptr)
			{
				if (option < static_cast<uint32_t>(filtering::options::http::HttpFilteringOption::NUMBER_OF_ENTRIES))
				{
					m_programWideOptions->SetIsHttpFilteringOptionEnabled(static_cast<filtering::options::http::HttpFilteringOption>(option), enabled);
				}				
			}
		}

		const bool HttpFilteringEngineControl::GetOptionEnabled(const uint32_t option) const
		{
			if (m_programWideOptions != nullptr)
			{
				if (option < static_cast<uint32_t>(filtering::options::http::HttpFilteringOption::NUMBER_OF_ENTRIES))
				{
					m_programWideOptions->GetIsHttpFilteringOptionEnabled(static_cast<filtering::options::http::HttpFilteringOption>(option));
				}
			}

			return false;
		}

		void HttpFilteringEngineControl::SetCategoryEnabled(const uint8_t category, const bool enabled)
		{
			if (m_programWideOptions != nullptr)
			{
				m_programWideOptions->SetIsHttpCategoryFiltered(category, enabled);
			}
		}

		const bool HttpFilteringEngineControl::GetCategoryEnabled(const uint8_t category) const
		{
			if (m_programWideOptions != nullptr)
			{
				m_programWideOptions->GetIsHttpCategoryFiltered(category);
			}

			return false;
		}

		const bool HttpFilteringEngineControl::LoadFilteringListFromFile(const std::string& filePath, const uint8_t listCategory, const bool flushExistingInCategory)
		{
			if (m_httpFilteringEngine != nullptr)
			{
				return m_httpFilteringEngine->LoadAbpFormattedListFromFile(filePath, listCategory, flushExistingInCategory);
			}

			return false;
		}

		const bool HttpFilteringEngineControl::LoadFilteringListFromString(const std::string& listString, const uint8_t listCategory, const bool flushExistingInCategory)
		{
			if (m_httpFilteringEngine != nullptr)
			{
				return m_httpFilteringEngine->LoadAbpFormattedListFromString(listString, listCategory, flushExistingInCategory);
			}

			return false;
		}

	} /* namespace httpengine */
} /* namespace te */
