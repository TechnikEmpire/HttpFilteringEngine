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

#include "BaseDiverter.hpp"

#include <string>

namespace te
{
	namespace httpengine
	{
		namespace mitm
		{
			namespace diversion
			{

				BaseDiverter::BaseDiverter(
					util::cb::FirewallCheckFunction firewallCheckCb,
					util::cb::MessageFunction onInfo,
					util::cb::MessageFunction onWarning,
					util::cb::MessageFunction onError
					) :
					util::cb::EventReporter(onInfo,	onWarning, onError),
					m_firewallCheckCb(firewallCheckCb)
				{
					m_httpListenerPort = 0;
					m_httpsListenerPort = 0;
					m_running = false;
				}

				BaseDiverter::~BaseDiverter()
				{

				}

				const uint16_t BaseDiverter::GetHttpListenerPort() const
				{
					return m_httpListenerPort;
				}

				void BaseDiverter::SetHttpListenerPort(const uint16_t port)
				{
					m_httpListenerPort = port;
				}

				const uint16_t BaseDiverter::GetHttpsListenerPort() const
				{
					return m_httpsListenerPort;
				}

				void BaseDiverter::SetHttpsListenerPort(const uint16_t port)
				{
					m_httpsListenerPort = port;
				}

				const bool BaseDiverter::IsV4AddressPrivate(const std::array<uint8_t, 4> bytes) const
				{
					switch (bytes[0])
					{
						case 10:
						{
							return true;
						}

						case 192:
						{
							return bytes[1] == 168;
						}

						case 172:
						{
							return (bytes[1] >= 16 && bytes[1] <= 31);
						}

						default:
							return false;
					}
				}

				const bool BaseDiverter::IsSocksProxyConnect(const uint8_t* payload, const size_t payloadSize) const
				{
					if (payload == nullptr || payloadSize < 8)
					{
						return false;
					}

					auto socksVersion = payload[0];

					switch (socksVersion)
					{
						case 4:
						{
							// Socks4 RFC:
							// http://ftp.icm.edu.pl/packages/socks/socks4/SOCKS4.protocol

							// External destination port number.
							uint16_t port = static_cast<uint16_t>((payload[2] << 8) | payload[3]);

							if (port == 80 || port == 443)
							{
								// External destination IP address.
								std::array<uint8_t, 4> extIp{ payload[4], payload[5], payload[6], payload[7] };

								if (!IsV4AddressPrivate(extIp))
								{
									// SOCKS4 connect detected.
									return true;
								}
							}
						}
						break;

						case 5:
						{
							// Socks5 RFC:
							// https://www.ietf.org/rfc/rfc1928.txt

							// o CONNECT X'01'
							// o BIND X'02'
							// o UDP ASSOCIATE X'03'
							auto command = payload[1];

							if (command == 1)
							{
								// o IP V4 address: X'01'
								// o DOMAINNAME: X'03'
								// o IP V6 address: X'04'
								auto addressType = payload[3];


								switch (addressType)
								{
								case 1:
								{
									if (payloadSize < 10)
									{
										// Payload can't possibly be holding IPV4 address + port number.
										return false;
									}

									uint16_t port = (uint16_t)((payload[8] << 8) | payload[9]);

									if (port == 80 || port == 443)
									{
										// External destination IP address.
										std::array<uint8_t, 4> extIp{ payload[4], payload[5], payload[6], payload[7] };

										if (!IsV4AddressPrivate(extIp))
										{
											// SOCKS5 IPV4 connect detected.
											return true;
										}
									}
								}
								break;

								case 3:
								{
									// The address field contains a fully-qualified domain name.  The first
									// octet of the address field contains the number of octets of name that
									// follow, there is no terminating NUL octet.

									auto domainLength = payload[4];

									if (payloadSize < (domainLength + 6))
									{
										// Domain length + 16 bit port number extends beyond the packet payload length.
										return false;
									}

									// We don't need the domain name, but here it is anyway.
									// std::string domainName(payload + 5, domainLength);
								
									uint16_t port = (uint16_t)((payload[5 + domainLength] << 8) | payload[6 + domainLength]);

									if (port == 80 || port == 443)
									{	
										// SOCKS5 domain connect to domain name detected.
										return true;
									}
								}
								break;

								case 4:
								{
									if (payloadSize < 22)
									{
										// Payload can't possibly be holding IPV6 address + port number.
										return false;
									}

									uint16_t port = (uint16_t)((payload[20] << 8) | payload[21]);

									if (port == 80 || port == 443)
									{
										// SOCKS5 IPV6 connect detected. Blocking.
										return true;
									}
								}
								break;

								default:
									return false;
								}
							}
						}
						break;

						default:
							return false;
					}

					return false;
				}

			} /* namespace diversion */
		}/* namespace mitm */
	}/* namespace httpengine */
}/* namespace te */
