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
