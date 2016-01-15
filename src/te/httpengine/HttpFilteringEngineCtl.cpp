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

#include "HttpFilteringEngineCtl.hpp"

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

#endif

#include "filtering/http/HttpFilteringEngine.hpp"
#include "mitm/diversion/BaseDiverter.hpp"

namespace te
{
	namespace httpengine
	{

		struct HttpFilteringEngineCtl::HttpListenerPimpl
		{

		};

		struct HttpFilteringEngineCtl::HttpsListenerPimpl
		{

		};

		HttpFilteringEngineCtl::HttpFilteringEngineCtl(
			FirewallCheckCallback firewallCb,
			ReportMessageCallback onInfo,
			ReportMessageCallback onWarn,
			ReportMessageCallback onError,
			ReportBlockedRequestCallback onRequestBlocked,
			ReportBlockedElementsCallback onElementsBlocked
			) : 
			m_firewallCheckCb(firewallCb),
			m_onInfoCb(onInfo),
			m_onWarnCb(onWarn),
			m_onErrorCb(onError),
			m_onRequestBlockedCb(onRequestBlocked),
			m_onElementsBlockedCb(onElementsBlocked)

		{

		}

		HttpFilteringEngineCtl::~HttpFilteringEngineCtl()
		{

		}

		void HttpFilteringEngineCtl::Start()
		{

		}

		void HttpFilteringEngineCtl::Stop()
		{

		}

		bool HttpFilteringEngineCtl::IsRunning() const
		{

		}

	} /* namespace te */
} /* namespace httpengine */


// C API. XXX TODO - Perhaps this should be separated out to another file?

te::httpengine::HttpFilteringEngineCtl* fe_ctl_create(
	FirewallCheckCallback firewallCb,
	ReportMessageCallback onInfo,
	ReportMessageCallback onWarn,
	ReportMessageCallback onError,
	ReportBlockedRequestCallback onRequestBlocked,
	ReportBlockedElementsCallback onElementsBlocked
	)
{

	#if BOOST_OS_WINDOWS
		#ifndef NDEBUG
			assert(firewallCb != nullptr && u8"In fe_ctl_create(FirewallCheckCallback, ReportMessageCallback, \
						ReportMessageCallback, ReportMessageCallback, ReportBlockedRequestCallback, \
						ReportBlockedElementsCallback) - On Windows, a valid firewall callback is required!");
		#else
			if (firewallCb == nullptr)
			{
				throw new std::runtime_error(u8"In fe_ctl_create(FirewallCheckCallback, ReportMessageCallback, \
						ReportMessageCallback, ReportMessageCallback, ReportBlockedRequestCallback, \
						ReportBlockedElementsCallback) - On Windows, a valid firewall callback is required!");
			}
		#endif
	#endif

	te::httpengine::HttpFilteringEngineCtl* inst = new te::httpengine::HttpFilteringEngineCtl(
		firewallCb,
		onInfo,
		onWarn,
		onError,
		onRequestBlocked,
		onElementsBlocked
		);

	#ifndef NDEBUG
		assert(inst != nullptr && u8"In fe_ctl_create(FirewallCheckCallback, ReportMessageCallback, \
				ReportMessageCallback, ReportMessageCallback, ReportBlockedRequestCallback, \
				ReportBlockedElementsCallback) - Failed to allocate new HttpFilteringEngineCtl instance!");
	#else
		if (inst == nullptr)
		{
			throw new std::runtime_error(u8"In fe_ctl_create(FirewallCheckCallback, ReportMessageCallback, \
				ReportMessageCallback, ReportMessageCallback, ReportBlockedRequestCallback, \
				ReportBlockedElementsCallback) - Failed to allocate new HttpFilteringEngineCtl instance!");
		}
	#endif

	return inst;
}

void fe_ctl_destroy(te::httpengine::HttpFilteringEngineCtl* ptr)
{	
	delete ptr;
}

void fe_ctl_start(te::httpengine::HttpFilteringEngineCtl* ptr)
{
	#ifndef NDEBUG
		assert(ptr != nullptr && u8"In fe_ctl_start(te::httpengine::HttpFilteringEngineCtl*) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
	#else
		if (ptr == nullptr)
		{
			throw new std::runtime_error(u8"In fe_ctl_start(te::httpengine::HttpFilteringEngineCtl*) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
		}
	#endif

	ptr->Start();
}

void fe_ctl_stop(te::httpengine::HttpFilteringEngineCtl* ptr)
{
	#ifndef NDEBUG
		assert(ptr != nullptr && u8"In fe_ctl_stop(te::httpengine::HttpFilteringEngineCtl*) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
	#else
		if (ptr == nullptr)
		{
			throw new std::runtime_error(u8"In fe_ctl_stop(te::httpengine::HttpFilteringEngineCtl*) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
		}
	#endif

	ptr->Stop();
}

bool fe_ctl_is_running(te::httpengine::HttpFilteringEngineCtl* ptr)
{
	#ifndef NDEBUG
		assert(ptr != nullptr && u8"In fe_ctl_is_running(te::httpengine::HttpFilteringEngineCtl*) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
	#else
		if (ptr == nullptr)
		{
			throw new std::runtime_error(u8"In fe_ctl_is_running(te::httpengine::HttpFilteringEngineCtl*) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
		}
	#endif

	return ptr->IsRunning();
}

uint16_t fe_ctl_get_http_listener_port(te::httpengine::HttpFilteringEngineCtl* ptr)
{
	#ifndef NDEBUG
		assert(ptr != nullptr && u8"In fe_ctl_get_http_listener_port(te::httpengine::HttpFilteringEngineCtl*) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
	#else
		if (ptr == nullptr)
		{
			throw new std::runtime_error(u8"In fe_ctl_get_http_listener_port(te::httpengine::HttpFilteringEngineCtl*) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
		}
	#endif
}

void fe_ctl_set_http_listener_port(te::httpengine::HttpFilteringEngineCtl* ptr, const uint16_t val)
{
	// If we're already running, user has to restart to see changes take effect. User is amply
	// notified in header comments.

	#ifndef NDEBUG
		assert(ptr != nullptr && u8"In fe_ctl_set_http_listener_port(te::httpengine::HttpFilteringEngineCtl*, const uint16_t) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
	#else
		if (ptr == nullptr)
		{
			throw new std::runtime_error(u8"In fe_ctl_set_http_listener_port(te::httpengine::HttpFilteringEngineCtl*, const uint16_t) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
		}
	#endif
}

uint16_t fe_ctl_get_https_listener_port(te::httpengine::HttpFilteringEngineCtl* ptr)
{
	#ifndef NDEBUG
		assert(ptr != nullptr && u8"In fe_ctl_get_https_listener_port(te::httpengine::HttpFilteringEngineCtl*) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
	#else
		if (ptr == nullptr)
		{
			throw new std::runtime_error(u8"In fe_ctl_get_https_listener_port(te::httpengine::HttpFilteringEngineCtl*) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
		}
	#endif
}

void fe_ctl_set_https_listener_port(te::httpengine::HttpFilteringEngineCtl* ptr, const uint16_t val)
{
	// If we're already running, user has to restart to see changes take effect. User is amply
	// notified in header comments.

	#ifndef NDEBUG
		assert(ptr != nullptr && u8"In fe_ctl_set_https_listener_port(te::httpengine::HttpFilteringEngineCtl*, const uint16_t) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
	#else
		if (ptr == nullptr)
		{
			throw new std::runtime_error(u8"In fe_ctl_set_https_listener_port(te::httpengine::HttpFilteringEngineCtl*, const uint16_t) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
		}
	#endif
}

bool fe_ctl_get_option(te::httpengine::HttpFilteringEngineCtl* ptr, const uint32_t optionId)
{
	#ifndef NDEBUG
		assert(ptr != nullptr && u8"In fe_ctl_get_option(te::httpengine::HttpFilteringEngineCtl*, const uint32_t) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
	#else
		if (ptr == nullptr)
		{
			throw new std::runtime_error(u8"In fe_ctl_get_option(te::httpengine::HttpFilteringEngineCtl*, const uint32_t) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
		}
	#endif
}

void fe_ctl_set_option(te::httpengine::HttpFilteringEngineCtl* ptr, const uint32_t optionId, const bool val)
{
	#ifndef NDEBUG
		assert(ptr != nullptr && u8"In fe_ctl_set_option(te::httpengine::HttpFilteringEngineCtl*, const uint32_t, const bool) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
	#else
		if (ptr == nullptr)
		{
			throw new std::runtime_error(u8"In fe_ctl_set_option(te::httpengine::HttpFilteringEngineCtl*, const uint32_t, const bool) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
		}
	#endif
}

bool fe_ctl_get_category(te::httpengine::HttpFilteringEngineCtl* ptr, const uint8_t categoryId)
{
	#ifndef NDEBUG
		assert(ptr != nullptr && u8"In fe_ctl_get_category(te::httpengine::HttpFilteringEngineCtl*, const uint8_t) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
	#else
		if (ptr == nullptr)
		{
			throw new std::runtime_error(u8"In fe_ctl_get_category(te::httpengine::HttpFilteringEngineCtl*, const uint8_t) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
		}
	#endif


}

void fe_ctl_set_category(te::httpengine::HttpFilteringEngineCtl* ptr, const uint8_t categoryId, const bool val)
{
	#ifndef NDEBUG
		assert(ptr != nullptr && u8"In fe_ctl_set_category(te::httpengine::HttpFilteringEngineCtl*, const uint8_t, const bool) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
	#else
		if (ptr == nullptr)
		{
			throw new std::runtime_error(u8"In fe_ctl_set_category(te::httpengine::HttpFilteringEngineCtl*, const uint8_t, const bool) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
		}
	#endif


}

bool fe_ctl_load_list_from_file(
	te::httpengine::HttpFilteringEngineCtl* ptr,
	const char* filePath,
	const size_t filePathLength,
	const uint8_t listCategory
	)
{
	#ifndef NDEBUG
		assert(ptr != nullptr && u8"In fe_ctl_load_list_from_file(te::httpengine::HttpFilteringEngineCtl*, const char*, const size_t, const uint8_t) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
		assert(filePath != nullptr && u8"In fe_ctl_load_list_from_file(te::httpengine::HttpFilteringEngineCtl*, const char*, const size_t, const uint8_t) - Supplied file path ptr is nullptr!");
	#else
		if (ptr == nullptr)
		{
			throw new std::runtime_error(u8"In fe_ctl_set_category(te::httpengine::HttpFilteringEngineCtl*, const char*, const size_t, const uint8_t) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
		}
		if (filePath == nullptr)
		{
			throw new std::runtime_error(u8"In fe_ctl_set_category(te::httpengine::HttpFilteringEngineCtl*, const char*, const size_t, const uint8_t) - Supplied file path ptr is nullptr!");
		}
	#endif
}

bool fe_ctl_load_list_from_string(
	te::httpengine::HttpFilteringEngineCtl* ptr,
	const char* listString,
	const size_t listStringLength,
	const uint8_t listCategory
	)
{
	#ifndef NDEBUG
		assert(ptr != nullptr && u8"In fe_ctl_load_list_from_file(te::httpengine::HttpFilteringEngineCtl*, const char*, const size_t, const uint8_t) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
		assert(listString != nullptr && u8"In fe_ctl_load_list_from_file(te::httpengine::HttpFilteringEngineCtl*, const char*, const size_t, const uint8_t) - Supplied list string ptr is nullptr!");
	#else
		if (ptr == nullptr)
		{
			throw new std::runtime_error(u8"In fe_ctl_set_category(te::httpengine::HttpFilteringEngineCtl*, const char*, const size_t, const uint8_t) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
		}
		if (listString == nullptr)
		{
			throw new std::runtime_error(u8"In fe_ctl_set_category(te::httpengine::HttpFilteringEngineCtl*, const char*, const size_t, const uint8_t) - Supplied list string ptr is nullptr!");
		}
	#endif

}
