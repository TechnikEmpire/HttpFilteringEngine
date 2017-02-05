/*
* Copyright © 2017 Jesse Nicholson
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

#include "DiversionControl.hpp"

#include <boost/predef/os.h>

#if BOOST_OS_WINDOWS
#include "impl/win/WinDiverter.hpp"
#elif BOOST_OS_ANDROID
#include "impl/android/AndroidDiverter.hpp"
#endif

#include <stdexcept>
#include <cassert>

namespace te
{
	namespace httpengine
	{
		namespace mitm
		{
			namespace diversion
			{

				DiversionControl::DiversionControl(
					util::cb::FirewallCheckFunction firewallCheckCb,
					util::cb::MessageFunction onInfo,
					util::cb::MessageFunction onWarning,
					util::cb::MessageFunction onError
					) : 
					util::cb::EventReporter(
						onInfo,
						onWarning,
						onError
						)
				{
					#if BOOST_OS_WINDOWS
						m_diverter.reset(new WinDiverter(firewallCheckCb, onInfo, onWarning, onError));
					#elif BOOST_OS_ANDROID
						m_diverter.reset(new AndroidDiverter(onInfo, onWarning, onError));
					#endif	

					#ifndef NDEBUG
						assert(m_diverter != nullptr && u8"In DiversionControl::DiversionControl(util::cb::MessageFunction, util::cb::MessageFunction, util::cb::MessageFunction) - Failed to allocate diverter class");
					#else
						if (m_diverter == nullptr)
						{
							throw std::runtime_error(u8"In DiversionControl::DiversionControl(util::cb::MessageFunction, util::cb::MessageFunction, util::cb::MessageFunction) - Failed to allocate diverter class");
						}
					#endif
				}

				DiversionControl::~DiversionControl()
				{

				}

				const uint16_t DiversionControl::GetHttpListenerPort() const
				{
					return m_diverter->GetHttpListenerPort();
				}

				void DiversionControl::SetHttpListenerPort(const uint16_t port)
				{
					m_diverter->SetHttpListenerPort(port);
				}

				const uint16_t DiversionControl::GetHttpsListenerPort() const
				{
					return m_diverter->GetHttpsListenerPort();
				}

				void DiversionControl::SetHttpsListenerPort(const uint16_t port)
				{
					m_diverter->SetHttpsListenerPort(port);
				}

				void DiversionControl::Run()
				{
					m_diverter->Run();
				}

				void DiversionControl::Stop()
				{
					m_diverter->Stop();
				}

				const bool DiversionControl::IsRunning() const
				{
					return m_diverter->IsRunning();
				}

			} /* namespace diversion */
		}/* namespace mitm */
	}/* namespace httpengine */
}/* namespace te */
