/*
* Copyright © 2017 Jesse Nicholson
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

#include "HttpFilteringEngineManaged.hpp"

#pragma unmanaged
#include "HttpFilteringEngineCAPI.h"
#pragma managed

namespace Te {

	namespace HttpFilteringEngine
	{

		Engine::Engine(FirewallCheckHandler^ firewallCheckFunc, HttpMessageBeginHandler^ httpMessageBeginFunc, HttpMessageEndHandler^ httpMessageEndFunc, System::String^ caBundleAbsPath, uint16_t httpListenerPort, uint16_t httpsListenerPort, uint32_t numThreads)
		{
			m_onFirewallCallback = firewallCheckFunc;
			m_onHttpMessageBeginCallback = httpMessageBeginFunc;
			m_onHttpMessageEndCallback = httpMessageEndFunc;
			CaBundleAbsolutePath = caBundleAbsPath;			
			HttpListenerPort = httpListenerPort;
			HttpsListenerPort = httpsListenerPort;
			m_numThreads = numThreads;
			Init();
		}

		Engine::~Engine()
		{
			if (m_handle != nullptr)
			{
				fe_ctl_destroy_unsafe(m_handle);
				m_handle = nullptr;
			}

			this->!Engine();
		}

		Engine::!Engine()
		{	
		}

		System::String^ Engine::CaBundleAbsolutePath::get()
		{
			return m_caBundleAbsPath;
		}

		void Engine::CaBundleAbsolutePath::set(System::String^ value)
		{
			m_caBundleAbsPath = value;
		}

		uint16_t Engine::HttpListenerPort::get()
		{
			// Look at the notes in "unmanaged" side. We only store the port to keep its value
			// between the time its supplied, and the time that the object is actually created.
			if (m_handle != nullptr)
			{
				return fe_ctl_get_http_listener_port(m_handle);
			}

			return 0;
		}

		void Engine::HttpListenerPort::set(uint16_t value)
		{
			m_httpListenerPort = value;
		}

		uint16_t Engine::HttpsListenerPort::get()
		{
			// Look at the notes in "unmanaged" side. We only store the port to keep its value
			// between the time its supplied, and the time that the object is actually created.
			if (m_handle != nullptr)
			{
				return fe_ctl_get_https_listener_port(m_handle);
			}

			return 0;
		}

		void Engine::HttpsListenerPort::set(uint16_t value)
		{
			m_httpsListenerPort = value;
		}

		bool Engine::IsRunning::get()
		{			
			if (m_handle != nullptr)
			{
				return fe_ctl_is_running(m_handle);
			}

			return false;
		}

		void Engine::Start()
		{
			if (m_handle != nullptr)
			{
				fe_ctl_start(m_handle);
			}
		}

		void Engine::Stop()
		{
			if (m_handle != nullptr)
			{
				fe_ctl_stop(m_handle);
			}
		}

		array<System::Byte>^ Engine::GetRootCaPEM()
		{
			if (m_handle != nullptr)
			{
				char* buff;
				size_t bsize;				
				fe_ctl_get_rootca_pem(m_handle, &buff, &bsize);

				if (bsize > 0)
				{
					array<System::Byte>^ ret = gcnew array<System::Byte>(bsize);

					pin_ptr<System::Byte> retpinned = &ret[0];

					memcpy(retpinned, buff, bsize);

					free(buff);

					return ret;
				}
			}

			return gcnew array<System::Byte>(0);
		}

		void Engine::Init()
		{

			if (m_onFirewallCallback == nullptr)
			{
				System::Exception^ err = gcnew System::Exception(u8"In void Engine::Init() - Nullptr provided for firewall permission check function. This is required!");
				throw err;
			}

			m_unmanagedFirewallCheckCallback = gcnew UnmanagedFirewallCheckCallback(this, &Engine::UnmanagedFirewallCheck);			
			m_unmanagedOnInfoCallback = gcnew UnmanagedMessageCallback(this, &Engine::UnmanagedOnInfo);
			m_unmanagedOnWarningCallback = gcnew UnmanagedMessageCallback(this, &Engine::UnmanagedOnWarning);
			m_unmanagedOnErrorCallback = gcnew UnmanagedMessageCallback(this, &Engine::UnmanagedOnError);

			m_unmanagedOnHttpMessageBeginCallback = gcnew UnmanagedOnHttpMessageBeginCallback(this, &Engine::UnmanagedHttpMessageBegin);
			m_unmanagedOnHttpMessageEndCallback = gcnew UnmanagedOnHttpMessageEndCallback(this, &Engine::UnmanagedHttpMessageEnd);

			auto firewallCbPtr = Marshal::GetFunctionPointerForDelegate(m_unmanagedFirewallCheckCallback);
			auto infoCbPtr = Marshal::GetFunctionPointerForDelegate(m_unmanagedOnInfoCallback);
			auto warnCbPtr = Marshal::GetFunctionPointerForDelegate(m_unmanagedOnWarningCallback);
			auto errorCbPtr = Marshal::GetFunctionPointerForDelegate(m_unmanagedOnErrorCallback);

			auto httpBeginCbPtr = Marshal::GetFunctionPointerForDelegate(m_unmanagedOnHttpMessageBeginCallback);
			auto httpEndCbPtr = Marshal::GetFunctionPointerForDelegate(m_unmanagedOnHttpMessageEndCallback);

			std::string caBundlePathStr(u8"none");

			if (!System::String::IsNullOrEmpty(CaBundleAbsolutePath) && !System::String::IsNullOrWhiteSpace(CaBundleAbsolutePath))
			{
				caBundlePathStr = msclr::interop::marshal_as<std::string>(CaBundleAbsolutePath);
			}

			m_handle = fe_ctl_create(
				static_cast<FirewallCheckCallback>(firewallCbPtr.ToPointer()),
				caBundlePathStr.c_str(),
				caBundlePathStr.size(),
				HttpListenerPort,
				HttpsListenerPort,
				m_numThreads,
				static_cast<HttpMessageBeginCallback>(httpBeginCbPtr.ToPointer()),
				static_cast<HttpMessageEndCallback>(httpEndCbPtr.ToPointer()),
				static_cast<ReportMessageCallback>(infoCbPtr.ToPointer()),
				static_cast<ReportMessageCallback>(warnCbPtr.ToPointer()),
				static_cast<ReportMessageCallback>(errorCbPtr.ToPointer())
				);

			if (m_handle == nullptr)
			{
				System::Exception^ err = gcnew System::Exception(u8"In void Engine::Init() - Failed to allocate native handle.");
				throw err;
			}
		}

		bool Engine::UnmanagedFirewallCheck(const char* binaryAbsolutePath, const size_t binaryAbsolutePathLength)
		{
			if (m_onFirewallCallback != nullptr && binaryAbsolutePath != nullptr)
			{
				System::String^ binaryName = gcnew System::String(binaryAbsolutePath, 0, static_cast<int>(binaryAbsolutePathLength));
				return m_onFirewallCallback(binaryName);
			}

			return false;
		}

		void Engine::UnmanagedOnInfo(const char* message, const size_t messageLength)
		{
			if (message != nullptr)
			{
				System::String^ msg = gcnew System::String(message, 0, static_cast<int>(messageLength));
				OnInfo(msg);
			}
		}

		void Engine::UnmanagedOnWarning(const char* message, const size_t messageLength)
		{
			if (message != nullptr)
			{
				System::String^ msg = gcnew System::String(message, 0, static_cast<int>(messageLength));
				OnWarning(msg);
			}
		}

		void Engine::UnmanagedOnError(const char* message, const size_t messageLength)
		{
			if (message != nullptr)
			{
				System::String^ msg = gcnew System::String(message, 0, static_cast<int>(messageLength));
				OnError(msg);
			}			
		}

		void Engine::UnmanagedHttpMessageBegin(
			const char* requestHeaders, const uint32_t requestHeadersLength, const char* requestBody, const uint32_t requestBodyLength,
			const char* responseHeaders, const uint32_t responseHeadersLength, const char* responseBody, const uint32_t responseBodyLength,
			uint32_t* nextAction, char** customBlockResponse, uint32_t* customBlockResponseLength
		)
		{
			System::String^ requestHeadersMStr = System::String::Empty;
			System::String^ responseHeadersMStr = System::String::Empty;

			array<System::Byte>^ requestBodyArr = gcnew array<System::Byte>(0);
			array<System::Byte>^ responseBodyArr = gcnew array<System::Byte>(0);

			if (requestHeaders != nullptr)
			{
				requestHeadersMStr = gcnew System::String(requestHeaders, 0, static_cast<int>(requestHeadersLength));
			}

			if (responseHeaders != nullptr)
			{
				responseHeadersMStr = gcnew System::String(responseHeaders, 0, static_cast<int>(responseHeadersLength));
			}

			if (requestBody != nullptr)
			{
				requestBodyArr = gcnew array<System::Byte>(requestBodyLength);
				System::Runtime::InteropServices::Marshal::Copy(IntPtr((void *)requestBody), requestBodyArr, 0, requestBodyLength);
			}

			if (responseBody != nullptr)
			{
				responseBodyArr = gcnew array<System::Byte>(responseBodyLength);
				System::Runtime::InteropServices::Marshal::Copy(IntPtr((void *)responseBody), responseBodyArr, 0, responseBodyLength);
			}

			ProxyNextAction nxt = ProxyNextAction::AllowAndIgnoreContent;
			array<System::Byte>^ customBlockedResponseManaged = nullptr;

			m_onHttpMessageBeginCallback(requestHeadersMStr, requestBodyArr, responseHeadersMStr, responseBodyArr, nxt, customBlockedResponseManaged);

			(*customBlockResponseLength) = 0;

			if (customBlockedResponseManaged != nullptr && customBlockedResponseManaged->Length > 0)
			{	
				*customBlockResponse = new char[customBlockedResponseManaged->Length];
				pin_ptr<unsigned char> pinned = &customBlockedResponseManaged[0];
				char* src = reinterpret_cast<char*>(pinned);
				std::copy(src, src + customBlockedResponseManaged->Length, *customBlockResponse);
				(*customBlockResponseLength) = customBlockedResponseManaged->Length;				
			}

			(*nextAction) = (*reinterpret_cast<uint32_t*>(&nxt));
		}

		void Engine::UnmanagedHttpMessageEnd(
			const char* requestHeaders, const uint32_t requestHeadersLength, const char* requestBody, const uint32_t requestBodyLength,
			const char* responseHeaders, const uint32_t responseHeadersLength, const char* responseBody, const uint32_t responseBodyLength,
			bool* shouldBlock, char** customBlockResponse, uint32_t* customBlockResponseLength
		)
		{
			System::String^ requestHeadersMStr = System::String::Empty;
			System::String^ responseHeadersMStr = System::String::Empty;

			array<System::Byte>^ requestBodyArr = gcnew array<System::Byte>(0);
			array<System::Byte>^ responseBodyArr = gcnew array<System::Byte>(0);

			if (requestHeaders != nullptr)
			{
				requestHeadersMStr = gcnew System::String(requestHeaders, 0, static_cast<int>(requestHeadersLength));
			}

			if (responseHeaders != nullptr)
			{
				responseHeadersMStr = gcnew System::String(responseHeaders, 0, static_cast<int>(responseHeadersLength));
			}

			if (requestBody != nullptr)
			{
				requestBodyArr = gcnew array<System::Byte>(requestBodyLength);
				System::Runtime::InteropServices::Marshal::Copy(IntPtr((void *)requestBody), requestBodyArr, 0, requestBodyLength);
			}

			if (responseBody != nullptr)
			{
				responseBodyArr = gcnew array<System::Byte>(responseBodyLength);
				System::Runtime::InteropServices::Marshal::Copy(IntPtr((void *)responseBody), responseBodyArr, 0, responseBodyLength);
			}

			bool shouldBlockManaged = false;
			array<System::Byte>^ customBlockedResponseManaged = nullptr;

			m_onHttpMessageEndCallback(requestHeadersMStr, requestBodyArr, responseHeadersMStr, responseBodyArr, shouldBlockManaged, customBlockedResponseManaged);

			(*customBlockResponseLength) = 0;

			if (customBlockedResponseManaged != nullptr && customBlockedResponseManaged->Length > 0)
			{
				*customBlockResponse = static_cast<char*>(new char[customBlockedResponseManaged->Length]);
				pin_ptr<unsigned char> pinned = &customBlockedResponseManaged[0];
				char* src = reinterpret_cast<char*>(pinned);
				std::copy(src, src + customBlockedResponseManaged->Length, *customBlockResponse);
				(*customBlockResponseLength) = customBlockedResponseManaged->Length;
			}

			if (shouldBlockManaged)
			{
				(*shouldBlock) = true;
			}
			else
			{
				(*shouldBlock) = false;
			}
		}
	}
}