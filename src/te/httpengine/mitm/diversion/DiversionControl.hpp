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

#pragma once

#include <memory>
#include <cstdint>
#include "../../util/cb/EventReporter.hpp"

namespace te
{
	namespace httpengine
	{
		namespace mitm
		{
			namespace diversion
			{
			
				/// <summary>
				/// Forward decl BaseDiverter.
				/// </summary>
				class BaseDiverter;

				/// <summary>
				/// The DiversionControl class is meant to serve as the static interface to
				/// polymorphic platform specific implementations of packet diversion capabilities,
				/// in order to divert packets to the listening proxy acceptors. This class offers a
				/// very simple interface, enabling configuration of underlying diverter classes.
				/// 
				/// Note that this constructor can throw std::runtime_error in the event that the
				/// underlying diverter fails to initialize correctly.
				/// </summary>
				class DiversionControl : util::cb::EventReporter
				{

				public:
					
					/// <summary>
					/// Constructs a new DiversionControl which will transparently handle loading
					/// and using the correct platform appropriate Diverter. This constructor should
					/// be expected to throw a std::runtime_error in the event that invalid
					/// arguments are supplied. For example, as the firewallCheckCb is required on
					/// most platforms, providing an invalid function here will result in a throw on
					/// most platforms.
					/// </summary>
					/// <param name="firewallCheckCb">
					/// Callback that the underlying packet diversion mechanism can use to verify
					/// that traffic intercepted from specific machine local binaries is permitted
					/// to be sent outbound from the device. Needed on most platforms for most
					/// implementations, so a valid function pointer is required here.
					/// </param>
					/// <param name="onInfo">
					/// Optional callback to receive informational messages regarding non-critical events.
					/// </param>
					/// <param name="onWarning">
					/// Optional callback to receive informational messages regarding potentially
					/// critical, but handled events.
					/// </param>
					/// <param name="onError">
					/// Optional callback to receive informational messages regarding critical, but
					/// handled events.
					/// </param>
					DiversionControl(
						util::cb::FirewallCheckFunction firewallCheckCb,
						util::cb::MessageFunction onInfo = nullptr,
						util::cb::MessageFunction onWarning = nullptr,
						util::cb::MessageFunction onError = nullptr
						);

					/// <summary>
					/// Default destructor.
					/// </summary>
					~DiversionControl();

					/// <summary>
					/// Gets the port number that the diverter is configured to sent identified HTTP
					/// flows to.
					/// </summary>
					/// <returns>
					/// The port number that the diverter is configured to sent identified HTTP
					/// flows to.
					/// </returns>
					const uint16_t GetHttpListenerPort() const;

					/// <summary>
					/// Sets the port number that the diverter is configured to sent identified HTTP
					/// flows to. Implemented using atomic intengers, can be called at any time to
					/// dynamically change where flows are directed.
					/// </summary>
					/// <param name="port">
					/// The port number that the diverter is to sent identified HTTP
					/// flows to.
					/// </param>
					void SetHttpListenerPort(const uint16_t port);

					/// <summary>
					/// Gets the port number that the diverter is configured to sent identified
					/// HTTPS flows to.
					/// </summary>
					/// <returns>
					/// The port number that the diverter is configured to sent identified HTTPS
					/// flows to.
					/// </returns>
					const uint16_t GetHttpsListenerPort() const;

					/// <summary>
					/// Sets the port number that the diverter is configured to sent identified
					/// HTTPS flows to. Implemented using atomic intengers, can be called at any
					/// time to dynamically change where flows are directed.
					/// </summary>
					/// <param name="port">
					/// The port number that the diverter is to sent identified HTTPS flows to.
					/// </param>
					void SetHttpsListenerPort(const uint16_t port);

					/// <summary>
					/// Initiates the packet diversion process. Should create one or more threads
					/// internally and return, not block indefinitely. This method should be
					/// expected to throw std::runtime_error in the event that the underlying
					/// diversion process failed to intitate. The ::what() member will contain
					/// details of the error.
					/// </summary>
					void Run();

					/// <summary>
					/// Stops the packet diversion process.
					/// </summary>
					void Stop();

					/// <summary>
					/// Indicates whether or not the packet diversion process is presently active.
					/// </summary>
					/// <returns>
					/// True if the packet diversion process is presently active, false otherwise.
					/// </returns>
					const bool IsRunning() const;

				private:

					std::unique_ptr<BaseDiverter> m_diverter;

				};

			} /* namespace diversion */
		}/* namespace mitm */
	}/* namespace httpengine */
}/* namespace te */

