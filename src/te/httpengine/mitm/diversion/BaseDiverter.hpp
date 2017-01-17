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

#include <atomic>
#include <array>
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
				/// The BaseDiverter serves as the base class for all platform dependent packet
				/// diversion mechanisms. For each supported platform, a specialized diversion class
				/// must be created and must inherit from this.
				/// 
				/// XXX TODO - Need port-independent protocol mapping for plain HTTP and TLS traffic,
				/// along with a flow tracking mechanism to properly support such a mechanism.
				/// </summary>
				class BaseDiverter : public util::cb::EventReporter
				{

					friend class DiversionControl;

				public:

					/// <summary>
					/// Default destructor.
					/// </summary>
					virtual ~BaseDiverter();

					/// <summary>
					/// No copy no move no thx.
					/// </summary>
					BaseDiverter(const BaseDiverter&) = delete;
					BaseDiverter(BaseDiverter&&) = delete;
					BaseDiverter& operator=(const BaseDiverter&) = delete;

					/// <summary>
					/// Gets the port number that the diverter is configured to sent identified HTTP
					/// flows to. 
					/// </summary>
					/// <returns>
					/// The port number that the diverter is configured to sent identified HTTP
					/// flows to.
					/// </returns>
					virtual const uint16_t GetHttpListenerPort() const;

					/// <summary>
					/// Sets the port number that the diverter is configured to sent identified HTTP
					/// flows to. Implemented using atomic intengers, can be called at any time to
					/// dynamically change where flows are directed.
					/// </summary>
					/// <param name="port">
					/// The port number that the diverter is to sent identified HTTP
					/// flows to.
					/// </param>
					virtual void SetHttpListenerPort(const uint16_t port);

					/// <summary>
					/// Gets the port number that the diverter is configured to sent identified
					/// HTTPS flows to.
					/// </summary>
					/// <returns>
					/// The port number that the diverter is configured to sent identified HTTPS
					/// flows to.
					/// </returns>
					virtual const uint16_t GetHttpsListenerPort() const;

					/// <summary>
					/// Sets the port number that the diverter is configured to sent identified
					/// HTTPS flows to. Implemented using atomic intengers, can be called at any
					/// time to dynamically change where flows are directed.
					/// </summary>
					/// <param name="port">
					/// The port number that the diverter is to sent identified HTTPS flows to.
					/// </param>
					virtual void SetHttpsListenerPort(const uint16_t port);

					/// <summary>
					/// Initiates the packet diversion process. Should create one or more threads
					/// internally and return, not block indefinitely. This method should be
					/// expected to throw std::runtime_error in the event that the underlying
					/// diversion process failed to intitate. The ::what() member will contain
					/// details of the error.
					/// </summary>
					virtual void Run() = 0;

					/// <summary>
					/// Stops the packet diversion process.
					/// </summary>
					virtual void Stop() = 0;

					/// <summary>
					/// Indicates whether or not the packet diversion process is presently active.
					/// </summary>
					/// <returns>
					/// True if the packet diversion process is presently active, false otherwise.
					/// </returns>
					virtual const bool IsRunning() const = 0;

				protected:

					BaseDiverter(
						util::cb::FirewallCheckFunction firewallCheckCb = nullptr,
						util::cb::MessageFunction onInfo = nullptr,
						util::cb::MessageFunction onWarning = nullptr,
						util::cb::MessageFunction onError = nullptr
						);

					/// <summary>
					/// Determines if the supplied IPV4 address is a private address or not. Note that this is
					/// </summary>
					/// <param name="bytes">
					/// The IPV4 address bytes.
					/// </param>
					/// <returns>
					/// True if the supplied IPV4 address is in a private range, false otherwise.
					/// </returns>
					const bool IsV4AddressPrivate(const std::array<uint8_t, 4> bytes) const;

					/// <summary>
					/// Determines if the supplied payload is a SOCKS v4 or v5 CONNECT request.
					/// </summary>
					/// <param name="payload">
					/// The payload to examine.
					/// </param>
					/// <param name="payloadSize">
					/// The size of the payload to examine.
					/// </param>
					/// <returns>
					/// True if the supplied payload contains a SOCKS v4 or v5 CONNECT request, false
					/// otherwise.
					/// </returns>
					const bool IsSocksProxyConnect(const uint8_t*  payload, const size_t payloadSize) const;

					/// <summary>
					/// The port that intercepted HTTP packets should be diverted to.
					/// </summary>
					std::atomic_uint16_t m_httpListenerPort;

					/// <summary>
					/// The port that intercepted HTTPS packets should be diverted to.
					/// </summary>
					std::atomic_uint16_t m_httpsListenerPort;

					/// <summary>
					/// Indicates whether or not the diversion process is presently running.
					/// Can/should be used to keep the diversion loop going.
					/// </summary>
					std::atomic_bool m_running;

					/// <summary>
					/// For some implementations, it's necessary to have a mechanism available by
					/// which we can determine if the traffic we're diverting to our proxy is
					/// allowed to have internet access. Otherwise, since our application is granted
					/// internet access, we would by default allow anyone and everyone who's traffic
					/// we intercept to pass freely to the internet. So, this method is demanded by
					/// Diverter implementations that require this type of check.
					/// </summary>
					util::cb::FirewallCheckFunction m_firewallCheckCb;

				};

			} /* namespace diversion */
		}/* namespace mitm */
	}/* namespace httpengine */
}/* namespace te */

