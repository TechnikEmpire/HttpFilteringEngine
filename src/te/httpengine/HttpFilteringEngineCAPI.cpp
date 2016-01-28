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

#include "HttpFilteringEngineCAPI.h"

#include "HttpFilteringEngineControl.hpp"

#include <boost/predef.h>

PHttpFilteringEngineCtl fe_ctl_create(
	FirewallCheckCallback firewallCb,
	const char* caBundleAbsolutePath,
	uint32_t caBundleAbsolutePathLength,
	uint16_t httpListenerPort,
	uint16_t httpsListenerPort,
	uint32_t numThread,
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

	if (numThread == 0)
	{
		numThread = std::thread::hardware_concurrency();
	}

	std::string caPath(u8"none");

	if (caBundleAbsolutePathLength > 0 && caBundleAbsolutePath != nullptr)
	{
		caPath = std::string(caBundleAbsolutePath, static_cast<size_t>(caBundleAbsolutePathLength));
	}

	PHttpFilteringEngineCtl inst = nullptr;

	bool success = false;
	try
	{
		inst = reinterpret_cast<PHttpFilteringEngineCtl>(new te::httpengine::HttpFilteringEngineControl(
			firewallCb,
			caPath,
			httpListenerPort,
			httpsListenerPort,
			numThread,
			onInfo,
			onWarn,
			onError,
			onRequestBlocked,
			onElementsBlocked
			));		

		#ifndef NDEBUG
			assert(inst != nullptr && u8"In fe_ctl_create(FirewallCheckCallback, ReportMessageCallback, \
					ReportMessageCallback, ReportMessageCallback, ReportBlockedRequestCallback, \
					ReportBlockedElementsCallback) - Failed to allocate new HttpFilteringEngineCtl instance!");
		#else
			// if (inst == nullptr)
			// {
			// 	throw new std::runtime_error(u8"In fe_ctl_create(FirewallCheckCallback, ReportMessageCallback, \
					// 		ReportMessageCallback, ReportMessageCallback, ReportBlockedRequestCallback, \
			// 		ReportBlockedElementsCallback) - Failed to allocate new HttpFilteringEngineCtl instance!");
			// }
		#endif

		success = true;
	}
	catch (std::exception& e)
	{

	}

	return inst;
}

void fe_ctl_destroy(PPHttpFilteringEngineCtl ptr)
{	
	delete reinterpret_cast<te::httpengine::HttpFilteringEngineControl*>(*ptr);
	*ptr = nullptr;
}

const bool fe_ctl_start(PHttpFilteringEngineCtl ptr)
{
	#ifndef NDEBUG
		assert(ptr != nullptr && u8"In fe_ctl_start(PHttpFilteringEngineCtl) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
	#else
		// if (ptr == nullptr)
		// {
		// 	throw new std::runtime_error(u8"In fe_ctl_start(PHttpFilteringEngineCtl) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
		// }
	#endif

	bool success = false;

	if (ptr != nullptr)
	{
		try
		{
			reinterpret_cast<te::httpengine::HttpFilteringEngineControl*>(ptr)->Start();

			success = true;
		}
		catch (std::exception& e)
		{

		}
	}

	return success;
}

void fe_ctl_stop(PHttpFilteringEngineCtl ptr)
{
	#ifndef NDEBUG
		assert(ptr != nullptr && u8"In fe_ctl_stop(PHttpFilteringEngineCtl) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
	#else
		//if (ptr == nullptr)
		//{
		//	throw new std::runtime_error(u8"In fe_ctl_stop(PHttpFilteringEngineCtl) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
		//}
	#endif

	bool success = false;

	try
	{
		if (ptr != nullptr)
		{
			reinterpret_cast<te::httpengine::HttpFilteringEngineControl*>(ptr)->Stop();

			success = true;
		}		
	}
	catch (std::exception& e)
	{

	}
}

const bool fe_ctl_is_running(PHttpFilteringEngineCtl ptr)
{
	#ifndef NDEBUG
		assert(ptr != nullptr && u8"In fe_ctl_is_running(PHttpFilteringEngineCtl) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
	#else
		//if (ptr == nullptr)
		//{
		//	throw new std::runtime_error(u8"In fe_ctl_is_running(PHttpFilteringEngineCtl) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
		//}
	#endif

	bool success = false;

	try
	{
		if (ptr != nullptr)
		{
			return reinterpret_cast<te::httpengine::HttpFilteringEngineControl*>(ptr)->IsRunning();
			success = true;
		}		
	}
	catch (std::exception& e)
	{

	}

	return success;
}

uint16_t fe_ctl_get_http_listener_port(PHttpFilteringEngineCtl ptr)
{
	#ifndef NDEBUG
		assert(ptr != nullptr && u8"In fe_ctl_get_http_listener_port(PHttpFilteringEngineCtl) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
	#else
		//if (ptr == nullptr)
		//{
		//	throw new std::runtime_error(u8"In fe_ctl_get_http_listener_port(PHttpFilteringEngineCtl) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
		//}
	#endif

	try
	{
		if (ptr != nullptr)
		{
			return reinterpret_cast<te::httpengine::HttpFilteringEngineControl*>(ptr)->GetHttpListenerPort();
		}		
	}
	catch (std::exception& e)
	{

	}

	return 0;
}

uint16_t fe_ctl_get_https_listener_port(PHttpFilteringEngineCtl ptr)
{
	#ifndef NDEBUG
		assert(ptr != nullptr && u8"In fe_ctl_get_https_listener_port(PHttpFilteringEngineCtl) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
	#else
		//if (ptr == nullptr)
		//{
		//	throw new std::runtime_error(u8"In fe_ctl_get_https_listener_port(PHttpFilteringEngineCtl) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
		//}
	#endif

	try
	{
		if (ptr != nullptr)
		{
			return reinterpret_cast<te::httpengine::HttpFilteringEngineControl*>(ptr)->GetHttpsListenerPort();
		}
	}
	catch (std::exception& e)
	{

	}

	return 0;
}

const bool fe_ctl_get_option(PHttpFilteringEngineCtl ptr, const uint32_t optionId)
{
	#ifndef NDEBUG
		assert(ptr != nullptr && u8"In fe_ctl_get_option(PHttpFilteringEngineCtl, const uint32_t) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
	#else
		//if (ptr == nullptr)
		//{
		//	throw new std::runtime_error(u8"In fe_ctl_get_option(PHttpFilteringEngineCtl, const uint32_t) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
		//}
	#endif

	bool success = false;

	try
	{
		if (ptr != nullptr)
		{
			success = reinterpret_cast<te::httpengine::HttpFilteringEngineControl*>(ptr)->GetOptionEnabled(optionId);
		}
	}
	catch (std::exception& e)
	{

	}

	return success;
}

void fe_ctl_set_option(PHttpFilteringEngineCtl ptr, const uint32_t optionId, const bool val)
{
	#ifndef NDEBUG
		assert(ptr != nullptr && u8"In fe_ctl_set_option(PHttpFilteringEngineCtl, const uint32_t, const bool) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
	#else
		//if (ptr == nullptr)
		//{
		//	throw new std::runtime_error(u8"In fe_ctl_set_option(PHttpFilteringEngineCtl, const uint32_t, const bool) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
		//}
	#endif

	bool success = false;

	try
	{
		if (ptr != nullptr)
		{
			reinterpret_cast<te::httpengine::HttpFilteringEngineControl*>(ptr)->SetOptionEnabled(optionId, val);
		}
	}
	catch (std::exception& e)
	{

	}
}

const bool fe_ctl_get_category(PHttpFilteringEngineCtl ptr, const uint8_t categoryId)
{
	#ifndef NDEBUG
		assert(ptr != nullptr && u8"In fe_ctl_get_category(PHttpFilteringEngineCtl, const uint8_t) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
	#else
		//if (ptr == nullptr)
		//{
		//	throw new std::runtime_error(u8"In fe_ctl_get_category(PHttpFilteringEngineCtl, const uint8_t) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
		//}
	#endif

	bool success = false;

	try
	{
		if (ptr != nullptr)
		{
			success = reinterpret_cast<te::httpengine::HttpFilteringEngineControl*>(ptr)->GetCategoryEnabled(categoryId);
		}
	}
	catch (std::exception& e)
	{

	}

	return success;
}

void fe_ctl_set_category(PHttpFilteringEngineCtl ptr, const uint8_t categoryId, const bool val)
{
	#ifndef NDEBUG
		assert(ptr != nullptr && u8"In fe_ctl_set_category(PHttpFilteringEngineCtl, const uint8_t, const bool) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
	#else
		//if (ptr == nullptr)
		//{
		//	throw new std::runtime_error(u8"In fe_ctl_set_category(PHttpFilteringEngineCtl, const uint8_t, const bool) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
		//}
	#endif

	try
	{
		if (ptr != nullptr)
		{
			reinterpret_cast<te::httpengine::HttpFilteringEngineControl*>(ptr)->SetCategoryEnabled(categoryId, val);
		}
	}
	catch (std::exception& e)
	{

	}
}

const bool fe_ctl_load_list_from_file(
	PHttpFilteringEngineCtl ptr,
	const char* filePath,
	const size_t filePathLength,
	const uint8_t listCategory,
	const bool flushExisting
	)
{
	#ifndef NDEBUG
		assert(ptr != nullptr && u8"In fe_ctl_load_list_from_file(PHttpFilteringEngineCtl, const char*, const size_t, const uint8_t) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
		assert(filePath != nullptr && u8"In fe_ctl_load_list_from_file(PHttpFilteringEngineCtl, const char*, const size_t, const uint8_t) - Supplied file path ptr is nullptr!");
	#else
		//if (ptr == nullptr)
		//{
		//	throw new std::runtime_error(u8"In fe_ctl_set_category(PHttpFilteringEngineCtl, const char*, const size_t, const uint8_t) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
		//}
		//if (filePath == nullptr)
		//{
		//	throw new std::runtime_error(u8"In fe_ctl_set_category(PHttpFilteringEngineCtl, const char*, const size_t, const uint8_t) - Supplied file path ptr is nullptr!");
		//}
	#endif

	bool success = false;

	try
	{
		if (ptr != nullptr && filePath != nullptr)
		{
			std::string filePathStr(filePath, filePathLength);			
			success = reinterpret_cast<te::httpengine::HttpFilteringEngineControl*>(ptr)->LoadFilteringListFromFile(filePathStr, listCategory, flushExisting);
		}
	}
	catch (std::exception& e)
	{

	}

	return success;
}

const bool fe_ctl_load_list_from_string(
	PHttpFilteringEngineCtl ptr,
	const char* listString,
	const size_t listStringLength,
	const uint8_t listCategory,
	const bool flushExisting
	)
{
	#ifndef NDEBUG
		assert(ptr != nullptr && u8"In fe_ctl_load_list_from_file(PHttpFilteringEngineCtl, const char*, const size_t, const uint8_t) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
		assert(listString != nullptr && u8"In fe_ctl_load_list_from_file(PHttpFilteringEngineCtl, const char*, const size_t, const uint8_t) - Supplied list string ptr is nullptr!");
	#else
		//if (ptr == nullptr)
		//{
		//	throw new std::runtime_error(u8"In fe_ctl_set_category(PHttpFilteringEngineCtl, const char*, const size_t, const uint8_t) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
		//}
		//if (listString == nullptr)
		//{
		//	throw new std::runtime_error(u8"In fe_ctl_set_category(PHttpFilteringEngineCtl, const char*, const size_t, const uint8_t) - Supplied list string ptr is nullptr!");
		//}
	#endif

	bool success = false;

	try
	{
		if (ptr != nullptr && listString != nullptr)
		{
			std::string fileString(listString, listStringLength);
			success = reinterpret_cast<te::httpengine::HttpFilteringEngineControl*>(ptr)->LoadFilteringListFromString(fileString, listCategory, flushExisting);
		}
	}
	catch (std::exception& e)
	{

	}

	return success;
}
