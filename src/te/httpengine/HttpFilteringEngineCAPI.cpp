/*
* Copyright © 2017 Jesse Nicholson
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

#pragma unmanaged

#include "HttpFilteringEngineCAPI.h"
#include "HttpFilteringEngineControl.hpp"
#include <iostream>

#include <boost/predef.h>

#if BOOST_OS_WINDOWS
	#include <WinSock2.h>
#endif


PVOID fe_ctl_create(
	FirewallCheckCallback firewallCb,
	const char* caBundleAbsolutePath,
	uint32_t caBundleAbsolutePathLength,
	uint16_t httpListenerPort,
	uint16_t httpsListenerPort,
	uint32_t numThread,	
	HttpMessageBeginCallback onMessageBegin,
	HttpMessageEndCallback onMessageEnd,
	ReportMessageCallback onInfo,
	ReportMessageCallback onWarn,
	ReportMessageCallback onError
	)
{

	#if BOOST_OS_WINDOWS
		#ifndef NDEBUG
			assert(firewallCb != nullptr && u8"On Windows, a valid firewall callback is required!");
		#endif

		
		WORD wVersionRequested = MAKEWORD(2, 0);
		WSADATA wsaData;
		int err = WSAStartup(wVersionRequested, &wsaData);

		// XXX TODO - Because of our non-existent error API, what can do here?
		if (err != 0)
		{
			return nullptr;
		}
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

	PVOID inst = nullptr;

	bool success = false;
	try
	{
		inst = static_cast<PVOID>(new te::httpengine::HttpFilteringEngineControl(
			firewallCb,
			caPath,
			httpListenerPort,
			httpsListenerPort,
			numThread,
			onMessageBegin,
			onMessageEnd,
			onInfo,
			onWarn,
			onError
			));		

		#ifndef NDEBUG
			assert(inst != nullptr && u8"In fe_ctl_create(FirewallCheckCallback, ReportMessageCallback, \
					ReportMessageCallback, ReportMessageCallback, ReportBlockedRequestCallback, \
					ReportBlockedElementsCallback) - Failed to allocate new HttpFilteringEngineCtl instance!");
		#endif

		success = true;
	}
	catch (std::exception& e)
	{
		std::cout << "error: " << e.what() << std::endl;
	}

	return inst;
}

void fe_ctl_destroy(PVOID* ptr)
{	
	te::httpengine::HttpFilteringEngineControl* cppPtr = static_cast<te::httpengine::HttpFilteringEngineControl*>(*ptr);

	if (cppPtr != nullptr)
	{		

		delete cppPtr;
	}

	*ptr = nullptr;

	#if BOOST_OS_WINDOWS
		WSACleanup();
	#endif
}

void fe_ctl_destroy_unsafe(PVOID ptr)
{
	te::httpengine::HttpFilteringEngineControl* cppPtr = static_cast<te::httpengine::HttpFilteringEngineControl*>(ptr);

	if (cppPtr != nullptr)
	{

		if (cppPtr->IsRunning())
		{
			cppPtr->Stop();
		}

		delete cppPtr;
	}

	#if BOOST_OS_WINDOWS
		WSACleanup();
	#endif
}

const bool fe_ctl_start(PVOID ptr)
{
	#ifndef NDEBUG
		assert(ptr != nullptr && u8"In fe_ctl_start(PVOID) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
	#endif

	bool success = false;

	if (ptr != nullptr)
	{
		try
		{
			static_cast<te::httpengine::HttpFilteringEngineControl*>(ptr)->Start();

			success = true;
		}
		catch (std::exception& e)
		{
			static_cast<te::httpengine::HttpFilteringEngineControl*>(ptr)->ReportError(e.what());
		}
	}

	assert(success == true && u8"In fe_ctl_start(PVOID) - Caught exception and failed to start.");

	return success;
}

void fe_ctl_stop(PVOID ptr)
{
	#ifndef NDEBUG
		assert(ptr != nullptr && u8"In fe_ctl_stop(PVOID) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
	#endif

	bool success = false;

	try
	{
		if (ptr != nullptr)
		{
			static_cast<te::httpengine::HttpFilteringEngineControl*>(ptr)->Stop();

			success = true;
		}		
	}
	catch (std::exception& e)
	{		
		static_cast<te::httpengine::HttpFilteringEngineControl*>(ptr)->ReportError(e.what());
	}

	assert(success == true && u8"In fe_ctl_stop(PVOID) - Caught exception and failed to stop.");
}

const bool fe_ctl_is_running(PVOID ptr)
{
	#ifndef NDEBUG
		assert(ptr != nullptr && u8"In fe_ctl_is_running(PVOID) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
	#endif

	bool success = false;

	try
	{
		if (ptr != nullptr)
		{
			return static_cast<te::httpengine::HttpFilteringEngineControl*>(ptr)->IsRunning();
		}		
	}
	catch (std::exception& e)
	{
		static_cast<te::httpengine::HttpFilteringEngineControl*>(ptr)->ReportError(e.what());
	}

	assert(success == true && u8"In fe_ctl_is_running(PVOID) - Caught exception and failed to check status.");

	return success;
}

uint16_t fe_ctl_get_http_listener_port(PVOID ptr)
{
	#ifndef NDEBUG
		assert(ptr != nullptr && u8"In fe_ctl_get_http_listener_port(PVOID) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
	#endif

	bool success = false;

	try
	{
		if (ptr != nullptr)
		{
			return static_cast<te::httpengine::HttpFilteringEngineControl*>(ptr)->GetHttpListenerPort();
		}		
	}
	catch (std::exception& e)
	{
		static_cast<te::httpengine::HttpFilteringEngineControl*>(ptr)->ReportError(e.what());
	}

	assert(success == true && u8"In fe_ctl_get_http_listener_port(PVOID) - Caught exception and failed to get HTTP listener port.");

	return 0;
}

uint16_t fe_ctl_get_https_listener_port(PVOID ptr)
{
	#ifndef NDEBUG
		assert(ptr != nullptr && u8"In fe_ctl_get_https_listener_port(PVOID) - Supplied HttpFilteringEngineCtl ptr is nullptr!");
	#endif

	bool success = false;

	try
	{
		if (ptr != nullptr)
		{
			return static_cast<te::httpengine::HttpFilteringEngineControl*>(ptr)->GetHttpsListenerPort();
		}
	}
	catch (std::exception& e)
	{
		static_cast<te::httpengine::HttpFilteringEngineControl*>(ptr)->ReportError(e.what());
	}

	assert(success == true && u8"In fe_ctl_get_https_listener_port(PVOID) - Caught exception and failed to get HTTPs listener port.");

	return 0;
}

void fe_ctl_get_rootca_pem(PVOID ptr, char** bufferPP, size_t* bufferSize)
{
	#ifndef NDEBUG
		assert(ptr != nullptr && u8"In fe_ctl_get_rootca_pem(char**, size_t*) - Supplied PVOID ptr is nullptr!");
		assert(bufferPP != nullptr && u8"In fe_ctl_get_rootca_pem(char**, size_t*) - Supplied buffer pointer-to-pointer is nullptr!");
		assert(bufferSize != nullptr && u8"In fe_ctl_get_rootca_pem(char**, size_t*) - Supplied buffer size pointer is nullptr!");
	#endif

	bool callSuccess = false;

	if (ptr && bufferPP && bufferSize)
	{
		try
		{
			auto ret = static_cast<te::httpengine::HttpFilteringEngineControl*>(ptr)->GetRootCertificatePEM();

			*bufferSize = ret.size();

			if (*bufferSize > 0)
			{
				if ((*bufferPP = static_cast<char*>(malloc(sizeof(ret[0]) * (*bufferSize)))) != nullptr)
				{
					std::copy(ret.begin(), ret.end(), (*bufferPP));
					callSuccess = true;
				}				
			}			
		}
		catch (std::exception& e)
		{
			static_cast<te::httpengine::HttpFilteringEngineControl*>(ptr)->ReportError(e.what());
		}
	}

	assert(callSuccess == true && u8"In fe_ctl_get_rootca_pem(...) - Caught exception and failed to fetch root CA certificate.");
}
