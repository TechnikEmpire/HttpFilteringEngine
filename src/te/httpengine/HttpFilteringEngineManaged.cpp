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

#include "HttpFilteringEngineManaged.hpp"

namespace Te {

	namespace HttpFilteringEngine
	{

		Engine::Engine(OnFirewallCheckCallback^ firewallCheckFunc, System::String^ caBundleAbsPath, uint16_t httpListenerPort, uint16_t httpsListenerPort, uint32_t numThreads)
		{
			m_onFirewallCallback = firewallCheckFunc;
			CaBundleAbsolutePath = caBundleAbsPath;
			HttpListenerPort = httpListenerPort;
			HttpsListenerPort = httpsListenerPort;
			m_numThreads = numThreads;
			Init();
		}

		Engine::~Engine()
		{
			this->!Engine();
		}

		Engine::!Engine()
		{
			if (m_handle != nullptr)
			{
				fe_ctl_destroy_unsafe(m_handle);
				m_handle = nullptr;
			}
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

		void Engine::LoadAbpFormattedFile(
			System::String^ listFilePath, 
			uint8_t listCategory,
			bool flushExistingInCategory,
			[Out] uint32_t% rulesLoaded,
			[Out] uint32_t% rulesFailed
			)
		{
			uint32_t succeeded = 0;
			uint32_t failed = 0;

			if (System::String::IsNullOrEmpty(listFilePath) || System::String::IsNullOrWhiteSpace(listFilePath))
			{
				System::Exception^ err = gcnew System::Exception(u8"In bool Engine::LoadAbpFormattedFile(System::String^, uint8_t, bool) - Provided list file path is either null or whitespace.");
				throw err;
			}

			if (listCategory == 0)
			{
				System::Exception^ err = gcnew System::Exception(u8"In bool Engine::LoadAbpFormattedFile(System::String^, uint8_t, bool) - Cannot specify zero as the category. Zero is reserved to indicate \"Do not block\".");
				throw err;
			}

			if (m_handle != nullptr)
			{				
				auto listPathStr = msclr::interop::marshal_as<std::string>(listFilePath);

				fe_ctl_load_list_from_file(m_handle, listPathStr.c_str(), listPathStr.size(), listCategory, flushExistingInCategory, &succeeded, &failed);
			}

			rulesLoaded = succeeded;
			rulesFailed = failed;
		}

		void Engine::LoadAbpFormattedString(
			System::String^ list, 
			uint8_t listCategory, 
			bool flushExistingInCategory,
			[Out] uint32_t% rulesLoaded,
			[Out] uint32_t% rulesFailed
			)
		{
			uint32_t succeeded = 0;
			uint32_t failed = 0;

			if (System::String::IsNullOrEmpty(list) || System::String::IsNullOrWhiteSpace(list))
			{
				System::Exception^ err = gcnew System::Exception(u8"In bool Engine::LoadAbpFormattedFile(System::String^, uint8_t, bool) - Provided list is either null or whitespace.");
				throw err;
			}

			if (listCategory == 0)
			{
				System::Exception^ err = gcnew System::Exception(u8"In bool Engine::LoadAbpFormattedFile(System::String^, uint8_t, bool) - Cannot specify zero as the category. Zero is reserved to indicate \"Do not block\".");
				throw err;
			}

			if (m_handle != nullptr)
			{
				auto listStr = msclr::interop::marshal_as<std::string>(list);

				fe_ctl_load_list_from_file(m_handle, listStr.c_str(), listStr.size(), listCategory, flushExistingInCategory, &succeeded, &failed);
			}

			rulesLoaded = succeeded;
			rulesFailed = failed;
		}

		bool Engine::IsOptionEnabled(uint32_t option)
		{
			if (m_handle != nullptr)
			{
				return fe_ctl_get_option(m_handle, option);
			}

			return false;
		}

		void Engine::SetOptionEnabled(uint32_t option, bool enabled)
		{
			if (m_handle != nullptr)
			{
				return fe_ctl_set_option(m_handle, option, enabled);
			}
		}

		bool Engine::IsCategoryEnabled(uint8_t category)
		{
			if (m_handle != nullptr)
			{
				return fe_ctl_get_category(m_handle, category);
			}

			return false;
		}

		void Engine::SetCategoryEnabled(uint8_t category, bool enabled)
		{
			if (category == 0)
			{
				return;
			}

			if (m_handle != nullptr)
			{
				return fe_ctl_set_category(m_handle, category, enabled);
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
			m_unmanagedOnRequestBlockedCallback = gcnew UnmanagedReportRequestBlockedCallback(this, &Engine::UnmanagedOnRequestBlocked);
			m_unmanagedOnElementsBlockedCallback = gcnew UnmanagedReportElementsBlockedCallback(this, &Engine::UnmanagedOnElementsBlocked);

			auto firewallCbPtr = Marshal::GetFunctionPointerForDelegate(m_unmanagedFirewallCheckCallback);
			auto infoCbPtr = Marshal::GetFunctionPointerForDelegate(m_unmanagedOnInfoCallback);
			auto warnCbPtr = Marshal::GetFunctionPointerForDelegate(m_unmanagedOnWarningCallback);
			auto errorCbPtr = Marshal::GetFunctionPointerForDelegate(m_unmanagedOnErrorCallback);
			auto blockedReqCbPtr = Marshal::GetFunctionPointerForDelegate(m_unmanagedOnRequestBlockedCallback);
			auto blockedElmCbPtr = Marshal::GetFunctionPointerForDelegate(m_unmanagedOnElementsBlockedCallback);

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
				static_cast<ReportMessageCallback>(infoCbPtr.ToPointer()),
				static_cast<ReportMessageCallback>(warnCbPtr.ToPointer()),
				static_cast<ReportMessageCallback>(errorCbPtr.ToPointer()),
				static_cast<ReportBlockedRequestCallback>(blockedReqCbPtr.ToPointer()),
				static_cast<ReportBlockedElementsCallback>(blockedElmCbPtr.ToPointer())
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

		void Engine::UnmanagedOnRequestBlocked(const uint8_t category, const uint32_t payloadSizeBlocked, const char* fullRequest, const size_t requestLength)
		{
			System::String^ req = nullptr;

			if (fullRequest != nullptr)
			{
				req = gcnew System::String(fullRequest, 0, static_cast<int>(requestLength));
			}
			else
			{
				req = gcnew System::String(u8"No request provided.");
			}

			OnRequestBlocked(category, payloadSizeBlocked, req);
		}

		void Engine::UnmanagedOnElementsBlocked(const uint32_t numElementsRemoved, const char* fullRequest, const size_t requestLength)
		{
			System::String^ req = nullptr;

			if (fullRequest != nullptr)
			{
				req = gcnew System::String(fullRequest, 0, static_cast<int>(requestLength));
			}
			else
			{
				req = gcnew System::String(u8"No request provided.");
			}

			OnElementsBlocked(numElementsRemoved, req);
		}
	}
}