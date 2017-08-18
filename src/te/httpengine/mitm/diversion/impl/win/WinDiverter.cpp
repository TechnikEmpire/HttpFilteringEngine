/*
* Copyright © 2017 Jesse Nicholson
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

#include "WinDiverter.hpp"

#include <stdexcept>
#include <unordered_map>
#include <algorithm>

namespace te
{
	namespace httpengine
	{
		namespace mitm
		{
			namespace diversion
			{
				const uint32_t WinDiverter::StandardHttpPort = htons(80);
				const uint32_t WinDiverter::StandardHttpsPort = htons(443);

				WinDiverter::WinDiverter(
					util::cb::FirewallCheckFunction firewallCheckCb,
					util::cb::MessageFunction onInfo,
					util::cb::MessageFunction onWarning,
					util::cb::MessageFunction onError
				) :
					BaseDiverter(
						firewallCheckCb,
						onInfo,
						onWarning,
						onError
					)
				{
					m_thisPid = GetCurrentProcessId();

					if (!m_firewallCheckCb)
					{
						throw std::runtime_error(u8"In WinDiverter::WinDiverter(...) - No valid firewall check callback was supplied.");
					}

					// Ensure our lists are filled with false as an initial
					// default value. There are known issues where we can't
					// just expect these values to be initialized to false.
					auto len = m_v4Shouldfilter.size();
					for (int i = 0; i < len; ++i)
					{
						m_v4Shouldfilter[i] = false;
						m_v6Shouldfilter[i] = false;
					}
				}

				WinDiverter::~WinDiverter()
				{
					
				}

				const uint16_t WinDiverter::GetHttpListenerPort() const
				{
					return ntohs(m_httpListenerPort);
				}

				void WinDiverter::SetHttpListenerPort(const uint16_t port)
				{
					m_httpListenerPort = htons(port);
				}

				const uint16_t WinDiverter::GetHttpsListenerPort() const
				{
					return ntohs(m_httpsListenerPort);
				}

				void WinDiverter::SetHttpsListenerPort(const uint16_t port)
				{
					m_httpsListenerPort = htons(port);
				}

				void WinDiverter::Run()
				{
					std::unique_lock<std::mutex> lock(m_startStopMutex);

					if (m_running == false)
					{
						// Firefox does some trickery at startup, talking to itself over the local loopback
						// address. WinDivert, the driver that powers this specific Diverter, can capture
						// loopback traffic. If we screw with this traffic at all, in the case of FireFox that is,
						// we'll end up trying to pipe loopback packets out to the public interface, which will
						// result of course in a failure, and these packets being sent to the void to die. This,
						// in turn, will cause Firefox to take over a minute to startup. Brutal. So, we add to
						// the filter to ignore all loopback sourced or destined packets. Slow startup aside,
						// we're also blowing away loopback traffic. Now that's just rude.

						static const char* FILTER_STRING = u8"outbound and tcp and ((ip and ip.SrcAddr != 127.0.0.1) or (ipv6 and ipv6.SrcAddr != ::1))";

						#ifdef HTTP_FE_BLOCK_TOR
							m_diversionHandle = WinDivertOpen(u8"outbound and tcp", WINDIVERT_LAYER_NETWORK, -1000, WINDIVERT_FLAG_NO_CHECKSUM);
						#else
							const char* errorStr;
							uint32_t errorPos;
							if (!WinDivertHelperCheckFilter(FILTER_STRING, WINDIVERT_LAYER_NETWORK, &errorStr, &errorPos))
							{
								ReportError(errorStr);
								std::string errzzz(u8"at pos");
								errzzz.append(std::to_string(errorPos));
								ReportError(errzzz);
							}

							m_diversionHandle = WinDivertOpen(FILTER_STRING, WINDIVERT_LAYER_NETWORK, -1000, WINDIVERT_FLAG_NO_CHECKSUM);
						#endif

						m_quicBlockHandle = WinDivertOpen(u8"udp and (udp.DstPort == 80 || udp.DstPort == 443)", WINDIVERT_LAYER_NETWORK, 0, WINDIVERT_FLAG_NO_CHECKSUM | WINDIVERT_FLAG_DROP);

						if (m_diversionHandle == INVALID_HANDLE_VALUE)
						{
							std::string errMessage("In WinDiverter::Run() - Failed to start Diversion, got invalid WinDivert handle with error:\t");
							errMessage.append(std::to_string(GetLastError()));

							throw std::runtime_error(errMessage.c_str());
						}

						if (m_quicBlockHandle == INVALID_HANDLE_VALUE)
						{
							std::string errMessage("In WinDiverter::Run() - Failed to start quic blocking diversion, got invalid WinDivert handle with error:\t");
							errMessage.append(std::to_string(GetLastError()));

							throw std::runtime_error(errMessage.c_str());
						}

						WinDivertSetParam(m_diversionHandle, WINDIVERT_PARAM_QUEUE_LEN, 8192);

						WinDivertSetParam(m_diversionHandle, WINDIVERT_PARAM_QUEUE_TIME, 2048);

						auto numLogicalCores = std::thread::hardware_concurrency();

						// We use one thread per logical core. Not sure about WinDivert internals,
						// but there's some documentation about Windows that states that for overlapped
						// IO we should be using 1 thread per logical core max and no more.
						for (unsigned int i = 0; i < numLogicalCores; ++i)
						{
							m_diversionThreads.emplace_back(std::thread{ &WinDiverter::RunDiversion, this, static_cast<LPVOID>(m_diversionHandle) });
						}

						m_running = true;
					}
				}

				void WinDiverter::Stop()
				{
					std::unique_lock<std::mutex> lock(m_startStopMutex);

					if (m_running == true)
					{
						m_running = false;

						for (auto& t : m_diversionThreads)
						{
							t.join();
						}

						m_diversionThreads.clear();

						if (m_diversionHandle != nullptr && m_diversionHandle != INVALID_HANDLE_VALUE)
						{
							WinDivertClose(m_diversionHandle);
							m_diversionHandle = INVALID_HANDLE_VALUE;
						}

						if (m_quicBlockHandle != nullptr && m_quicBlockHandle != INVALID_HANDLE_VALUE)
						{
							WinDivertClose(m_quicBlockHandle);
							m_quicBlockHandle = INVALID_HANDLE_VALUE;
						}
					}
				}

				const bool WinDiverter::IsRunning() const
				{
					return m_running;
				}

				void WinDiverter::RunDiversion(LPVOID diversionHandlePtr)
				{
					HANDLE divertHandle = static_cast<HANDLE>(diversionHandlePtr);

					WINDIVERT_ADDRESS addr;
					PacketBuffer readBuffer;
					PVOID payloadBuffer = nullptr;
					uint32_t payloadLength = 0;

					uint32_t recvLength = 0;

					PWINDIVERT_IPHDR ipV4Header = nullptr;
					PWINDIVERT_IPV6HDR ipV6Header = nullptr;
					PWINDIVERT_TCPHDR tcpHeader = nullptr;

					PMIB_TCPTABLE2 ipv4TcpTable = nullptr;
					DWORD ipv4TcpTableSize = 0;

					PMIB_TCP6TABLE2 ipv6TcpTable = nullptr;
					DWORD ipv6TcpTableSize = 0;

					std::array<uint8_t, 4> ipv4Copy;

#ifdef HTTP_FILTERING_ENGINE_USE_EX
					OVERLAPPED recvOverlapped;
					HANDLE recvEvent = nullptr;
					DWORD recvAsyncIoLen;
#endif

					bool isLocalIpv4 = false;

					while (m_running)
					{
						recvLength = 0;
						memset(&addr, 0, sizeof(addr));
					
#ifdef HTTP_FILTERING_ENGINE_USE_EX

						recvAsyncIoLen = 0;
						memset(&recvOverlapped, 0, sizeof(OVERLAPPED));
						recvEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

						if (recvEvent == nullptr)
						{
							std::string errMessage("In WinDiverter::RunDiversion(LPVOID) - While creating RecvEx event, got error:\t");
							errMessage.append(std::to_string(GetLastError()));
							ReportError(errMessage);
							continue;
						}

						recvOverlapped.hEvent = recvEvent;

						if (!WinDivertRecvEx(divertHandle, readBuffer.data(), PacketBufferLength, 0, &addr, &recvLength, &recvOverlapped))
						{
							auto err = GetLastError();
							if (err != ERROR_IO_PENDING)
							{
								std::string errMessage("In WinDiverter::RunDiversion(LPVOID) - During call to WinDivert RecvEx, got error:\t");
								errMessage.append(std::to_string(err));
								ReportError(errMessage);
								continue;
							}

							
							while (WaitForSingleObject(recvEvent, 1000) == WAIT_TIMEOUT)
							{

							}

							if (!GetOverlappedResult(divertHandle, &recvOverlapped, &recvAsyncIoLen, FALSE))
							{
								std::string errMessage("In WinDiverter::RunDiversion(LPVOID) - During call to WinDivert RecvEx, while fetching overlapped result, got error:\t");
								errMessage.append(std::to_string(GetLastError()));
								ReportError(errMessage);

								CloseHandle(recvEvent);
								continue;
							}

							// Success at long last!
							recvLength = recvAsyncIoLen;
							CloseHandle(recvEvent);
						}
#else

						if (!WinDivertRecv(divertHandle, readBuffer.data(), PacketBufferLength, &addr, &recvLength))
						{
							std::string errMessage("In WinDiverter::RunDiversion(LPVOID) - During call to WinDivert Recv, got error:\t");
							errMessage.append(std::to_string(GetLastError()));
							ReportError(errMessage);
							continue;
						}

#endif // #ifdef HTTP_FILTERING_ENGINE_USE_EX

						// Since our filter is set to be outbound and TCP only, we don't really need to check this
						// at all. But, in case the filter is modified later, it doesn't hurt.
						if (addr.Direction == WINDIVERT_DIRECTION_OUTBOUND)
						{	
							// We don't care what the return value is. False can be a valid return value
							// according to the docs. So we just fire it and check the validity of our
							// pointers after, and that's where we get our verification that this call
							// succeeded.
							WinDivertHelperParsePacket(readBuffer.data(), recvLength, &ipV4Header, &ipV6Header, nullptr, nullptr, &tcpHeader, nullptr, &payloadBuffer, &payloadLength);

							if (tcpHeader != nullptr && tcpHeader->Syn > 0)
							{
								// Brand new outbound connection. Grab the PID of the process
								// holding this port and map it.								
								if (ipV4Header != nullptr)
								{
									m_v4pidMap[tcpHeader->SrcPort] = GetPacketProcess(tcpHeader->SrcPort, ipV4Header->SrcAddr, &ipv4TcpTable, ipv4TcpTableSize);

									if (m_v4pidMap[tcpHeader->SrcPort] == m_thisPid)
									{
										// System process. Don't even bother.
										m_v4Shouldfilter[tcpHeader->SrcPort] = false;
									}
									else
									{
										if (m_v4pidMap[tcpHeader->SrcPort] == 4)
										{
											m_v4Shouldfilter[tcpHeader->SrcPort] = false;
										}
										else
										{
											auto procPath = GetPacketProcessBinaryPath(m_v4pidMap[tcpHeader->SrcPort].load());

											if (procPath.size() == 0)
											{
												// This is something we couldn't get a handle on. Since we can't do that
												// that's probably a bad sign (SYSTEM process maybe?), don't filter it.
												m_v4Shouldfilter[tcpHeader->SrcPort] = false;
											}
											else
											{
												m_v4Shouldfilter[tcpHeader->SrcPort] = m_firewallCheckCb(procPath.c_str(), procPath.size());
											}
										}
									}
								}

								if (ipV6Header != nullptr)
								{
									m_v6pidMap[tcpHeader->SrcPort] = GetPacketProcess(tcpHeader->SrcPort, ipV6Header->SrcAddr, &ipv6TcpTable, ipv6TcpTableSize);

									if (m_v6pidMap[tcpHeader->SrcPort] == m_thisPid)
									{	
										m_v6Shouldfilter[tcpHeader->SrcPort] = false;
									}
									else
									{
										if (m_v6pidMap[tcpHeader->SrcPort] == 4)
										{
											// System process. Don't even bother.
											m_v6Shouldfilter[tcpHeader->SrcPort] = false;
										}
										else
										{
											auto procPath = GetPacketProcessBinaryPath(m_v6pidMap[tcpHeader->SrcPort].load());
											if (procPath.size() == 0)
											{
												// This is something we couldn't get a handle on. Since we can't do that
												// that's probably a bad sign (SYSTEM process maybe?), don't filter it.
												m_v6Shouldfilter[tcpHeader->SrcPort] = false;
											}
											else
											{
												m_v6Shouldfilter[tcpHeader->SrcPort] = m_firewallCheckCb(procPath.c_str(), procPath.size());
											}
										}
										
									}
								}
							}


							// I put the checks for ipv4 and ipv6 as a double if statement rather
							// than an else if because I'm not sure how that would affect dual-mode
							// sockets. Perhaps it's possible for both headers to be defined.
							// Probably not, but since I don't know, I err on the side of awesome,
							// or uhh, something like that.

							// We check local packets for TOR/SOCKS packets here. However, if
							// we don't find something we want to block on local addresses, then
							// we want to skip these for the rest of the filtering and just
							// let them through.
							isLocalIpv4 = false;
							
							if (ipV4Header != nullptr && tcpHeader != nullptr)
							{
								// Let's explain the weird arcane logic here. First, we check if the current flow
								// should even be filtered. We do this, because there's a good chance that
								// this flow belongs to our proxy's connections, which we never
								// want to filter. If we didn't check this, then we would end up setting
								// the isLocalIpv4 flag to true on every single one of our proxy's
								// connections, and clients would never get packets ever because with
								// that flag set, the direction of the packets wouldn't be sorted.
								//
								// So, we check this, ensure it's actually something we want to filter.
								// Then, we check if the packet is destined for a local address. We
								// set the flag accordingly, and if true, then we will allow these packets
								// to go out uninterrupted.
								//
								// If false, who cares. Regardless of true or false, we check to see if this
								// is a TOR/SOCKS4/5 proxy CONNECT, and drop it if it is.
								//
								// Also note, by letting local/private address destined packets go, we
								// also solve the problem of private TLS connections using private TLS
								// self signed certs, such as logging into one's router. If we didn't
								// do this check and let these through, we would break such connections.
								if (m_v4Shouldfilter[tcpHeader->SrcPort])
								{
									ipv4Copy[0] = ipV4Header->DstAddr & 0xFF;
									ipv4Copy[1] = (ipV4Header->DstAddr >> 8) & 0xFF;
									ipv4Copy[2] = (ipV4Header->DstAddr >> 16) & 0xFF;
									ipv4Copy[3] = (ipV4Header->DstAddr >> 24) & 0xFF;

									isLocalIpv4 = IsV4AddressPrivate(ipv4Copy);

									if (isLocalIpv4)
									{
										#ifdef HTTP_FE_BLOCK_TOR
										if (payloadBuffer != nullptr)
										{

											if (IsSocksProxyConnect(static_cast<uint8_t*>(payloadBuffer), payloadLength))
											{
												// Skip past this packet all together. We refuse to allow
												// any other proxy to function because this is our castle.
												ReportInfo(u8"Blocking SOCKS proxy.");
												payloadBuffer = nullptr;
												payloadLength = 0;
												continue;
											}
										}
										#endif
									}
								}
							}

							if (!isLocalIpv4)							
							{
								if (ipV4Header != nullptr && tcpHeader != nullptr)
								{
									if (tcpHeader->SrcPort == m_httpListenerPort || tcpHeader->SrcPort == m_httpsListenerPort)
									{
										// Means that the data is originating from our proxy in response
										// to a client's request, which means it was originally meant to
										// go somewhere else. We need to reorder the data such as the
										// src and destination ports and addresses and divert it back
										// inbound, so it appears to be an inbound response from the
										// original external server.
										//
										// In our case, this is very easy to figure out, because we are
										// not yet doing any port independent protocol mapping and thus
										// are only diverting port 80 traffic to m_httpListenerPort, and
										// port 443 traffic to m_httpsListenerPort. However, XXX TODO -
										// When we start doing these things, we'll need a mechanism by
										// which to store the original port before we changed it. This
										// would have to be part of a proper flow tracking system.

										uint32_t dstAddr = ipV4Header->DstAddr;
										ipV4Header->DstAddr = ipV4Header->SrcAddr;
										ipV4Header->SrcAddr = dstAddr;

										tcpHeader->SrcPort = (tcpHeader->SrcPort == m_httpListenerPort) ? StandardHttpPort : StandardHttpsPort;

										addr.Direction = WINDIVERT_DIRECTION_INBOUND;
									}
									else if (tcpHeader->DstPort == StandardHttpPort || tcpHeader->DstPort == StandardHttpsPort)
									{
										// This means outbound traffic has been captured that we know for sure is
										// not coming from our proxy in response to a client, but we don't know that it
										// isn't the upstream portion of our proxy trying to fetch a response on behalf
										// of a connected client. So, we need to check if we have a cached result for
										// information about the binary generating the outbound traffic for two reasons.
										//
										// First, we need to ensure that it's not us, obviously. Secondly, we need to
										// ensure that the binary has been granted firewall access to generate outbound
										// traffic.

										if (m_v4Shouldfilter[tcpHeader->SrcPort])
										{
											// If the process was identified as a process that is permitted to access the
											// internet, and is not a system process or ourselves, then we divert its packets
											// back inbound to the local machine, changing the destination port appropriately.
											uint32_t dstAddress = ipV4Header->DstAddr;

											ipV4Header->DstAddr = ipV4Header->SrcAddr;
											ipV4Header->SrcAddr = dstAddress;

											addr.Direction = WINDIVERT_DIRECTION_INBOUND;

											tcpHeader->DstPort = (tcpHeader->DstPort == StandardHttpPort) ? m_httpListenerPort : m_httpsListenerPort;
										}
									}
								}

								// The ipV6 version works exactly the same, just with larger storage for the larger
								// addresses. Look at the ipv4 version notes for clarification on anything.
								if (ipV6Header != nullptr && tcpHeader != nullptr)
								{
									if (tcpHeader->SrcPort == m_httpListenerPort || tcpHeader->SrcPort == m_httpsListenerPort)
									{
										uint32_t dstAddr[4];
										dstAddr[0] = ipV6Header->DstAddr[0];
										dstAddr[1] = ipV6Header->DstAddr[1];
										dstAddr[2] = ipV6Header->DstAddr[2];
										dstAddr[3] = ipV6Header->DstAddr[3];

										ipV6Header->DstAddr[0] = ipV6Header->SrcAddr[0];
										ipV6Header->DstAddr[1] = ipV6Header->SrcAddr[1];
										ipV6Header->DstAddr[2] = ipV6Header->SrcAddr[2];
										ipV6Header->DstAddr[3] = ipV6Header->SrcAddr[3];

										ipV6Header->SrcAddr[0] = dstAddr[0];
										ipV6Header->SrcAddr[1] = dstAddr[1];
										ipV6Header->SrcAddr[2] = dstAddr[2];
										ipV6Header->SrcAddr[3] = dstAddr[3];

										tcpHeader->SrcPort = (tcpHeader->SrcPort == m_httpListenerPort) ? StandardHttpPort : StandardHttpsPort;

										addr.Direction = WINDIVERT_DIRECTION_INBOUND;
									}
									else if (tcpHeader->DstPort == StandardHttpPort || tcpHeader->DstPort == StandardHttpsPort)
									{
										if (m_v6Shouldfilter[tcpHeader->SrcPort])
										{
											uint32_t dstAddr[4];

											dstAddr[0] = ipV6Header->DstAddr[0];
											dstAddr[1] = ipV6Header->DstAddr[1];
											dstAddr[2] = ipV6Header->DstAddr[2];
											dstAddr[3] = ipV6Header->DstAddr[3];

											ipV6Header->DstAddr[0] = ipV6Header->SrcAddr[0];
											ipV6Header->DstAddr[1] = ipV6Header->SrcAddr[1];
											ipV6Header->DstAddr[2] = ipV6Header->SrcAddr[2];
											ipV6Header->DstAddr[3] = ipV6Header->SrcAddr[3];

											ipV6Header->SrcAddr[0] = dstAddr[0];
											ipV6Header->SrcAddr[1] = dstAddr[1];
											ipV6Header->SrcAddr[2] = dstAddr[2];
											ipV6Header->SrcAddr[3] = dstAddr[3];

											addr.Direction = WINDIVERT_DIRECTION_INBOUND;

											tcpHeader->DstPort = (tcpHeader->DstPort == StandardHttpPort) ? m_httpListenerPort : m_httpsListenerPort;
										}
									}
								}
							} // if(!isLocalIpv4)
						} // if (addr.Direction == WINDIVERT_DIRECTION_OUTBOUND)

						payloadBuffer = nullptr;
						payloadLength = 0;

						WinDivertHelperCalcChecksums(readBuffer.data(), recvLength, 0);

						if (!WinDivertSendEx(divertHandle, readBuffer.data(), recvLength, 0, &addr, nullptr, nullptr))
						{
							// XXX TODO - Perhaps report warning instead? This isn't exactly critical. Maybe a single
							// packet gets lost, maybe it completes under the hood. Either way we can do nothing, and
							// this should be expected to happen at least once.
							//
							// Update - Disabling this but leaving it here. This floods our logs when we block internet
							// on purpose.
							/*
							std::string errMessage("In WinDiverter::RunDiversion(LPVOID) - During call to WinDivert SendEx, got error:\t");
							errMessage.append(std::to_string(GetLastError()));
							ReportError(errMessage);
							*/
						}
					}// while (m_running)

					if (ipv4TcpTable != nullptr)
					{
						free(ipv4TcpTable);
					}

					if (ipv6TcpTable != nullptr)
					{
						free(ipv6TcpTable);
					}
				}

				std::string WinDiverter::GetPacketProcessBinaryPath(const unsigned long processId) const
				{
					if (processId == 4)
					{
						// OS process.
						return std::string(u8"SYSTEM");
					}

					HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);

					if (processHandle != nullptr && processHandle != INVALID_HANDLE_VALUE)
					{
						DWORD resSize = MAX_PATH;
						char filename[MAX_PATH];

						if (QueryFullProcessImageNameA(processHandle, 0, filename, &resSize) == 0)
						{
							std::string err(u8"In WinDiverter::GetPacketProcessBinaryPath(const unsigned long) - Failed to get binary path using pid ");
							err.append(std::to_string(processId)).append(u8".");
							ReportError(err);

							return std::string();
						}
						else
						{
							CloseHandle(processHandle);
							return std::string(filename);
						}
					}
					else
					{
						#ifndef NDEBUG
						std::string err(u8"In WinDiverter::GetPacketProcessBinaryPath(const unsigned long) - Failed to open process to query binary path using pid ");
						err.append(std::to_string(processId)).append(u8".");
						ReportError(err);
						#endif
					}

					return std::string();
				}

				DWORD WinDiverter::GetPacketProcess(uint16_t localPort, uint32_t localV4Address, PMIB_TCPTABLE2* table, DWORD& currentTableSize)
				{
					// We deliberately never permanently free the table on purpose. Eventually, this table will
					// reach a size where reallocations don't happen anymore, and we can recycle it.

					if (currentTableSize == 0)
					{
						currentTableSize = sizeof(MIB_TCPTABLE2);
						*table = static_cast<PMIB_TCPTABLE2>(malloc(currentTableSize));
					}

					if (*table == nullptr)
					{
						currentTableSize = 0;
						ReportError(u8"In WinDiverter::GetPacketProcess(uint16_t, uint32_t, PMIB_TCPTABLE2, DWORD&) - Failed to initialize table.");
						return 0;
					}

					DWORD dwRetVal = 0;

					if ((dwRetVal = GetTcpTable2(*table, &currentTableSize, FALSE)) == ERROR_INSUFFICIENT_BUFFER)
					{
						free(*table);
						*table = nullptr;

						*table = static_cast<PMIB_TCPTABLE2>(malloc(currentTableSize));

						if (*table == nullptr)
						{
							currentTableSize = 0;
							ReportError(u8"In WinDiverter::GetPacketProcess(uint16_t, uint32_t, PMIB_TCPTABLE2, DWORD&) - Failed to resize table.");
							return 0;
						}

						dwRetVal = GetTcpTable2(*table, &currentTableSize, FALSE);
					}

					if (dwRetVal == NO_ERROR)
					{
						// Table members, spare things like dwOwningPid, are in network order aka big endian.
						for (DWORD i = 0; i < (*table)->dwNumEntries; ++i)
						{
							// The reason why we accept zero as the address is that it is equal to "0.0.0.0:PORT", so
							// it counts.
							if ((*table)->table[i].dwLocalAddr == 0 || localV4Address == 0 || (*table)->table[i].dwLocalAddr == localV4Address)
							{
								// See https://msdn.microsoft.com/en-us/library/windows/desktop/aa366909(v=vs.85).aspx
								// Upper bits may contain junk data.
								if (((*table)->table[i].dwLocalPort & 0xFFFF) == localPort)
								{
									return (*table)->table[i].dwOwningPid;
								}
							}
						}
					}
					else
					{
						ReportError(u8"In WinDiverter::GetPacketProcess(uint16_t, uint32_t, PMIB_TCPTABLE2, DWORD&) - Failed to populate table.");

						if (*table != nullptr)
						{
							free(*table);
							*table = nullptr;
						}

						currentTableSize = 0;
					}

					// We consider 4 to always be a system process. So, let's default to
					// 4 here. If we didn't get an error somewhere along the way, then
					// lets assume it's the SYSTEM.
					ReportWarning("In WinDiverter::GetPacketProcess(uint16_t, uint32_t, PMIB_TCPTABLE2, DWORD&) - Was unable to process to port matching. Assuming SYSTEM process.");
					return 4;
				}

				DWORD WinDiverter::GetPacketProcess(uint16_t localPort, uint32_t* localV6Address, PMIB_TCP6TABLE2* table, DWORD& currentTableSize)
				{
					// We deliberately never permanently free the table on purpose. Eventually, this table will
					// reach a size where reallocations don't happen anymore, and we can recycle it.

					if (!table)
					{
						ReportError(u8"In WinDiverter::GetPacketProcess(uint16_t, uint32_t[4], PMIB_TCP6TABLE2, DWORD&) - Expected pointer to TABLE structure, got nullptr!");
						return 0;
					}

					if (localV6Address == nullptr)
					{
						ReportError(u8"In WinDiverter::GetPacketProcess(uint16_t, uint32_t[4], PMIB_TCP6TABLE2, DWORD&) - Expected uint32_t array with length of four for localV6Address, got nullptr!");
						return 0;
					}

					if (currentTableSize == 0)
					{
						currentTableSize = sizeof(MIB_TCP6TABLE2);
						*table = static_cast<PMIB_TCP6TABLE2>(malloc(currentTableSize));
					}

					if (*table == nullptr)
					{
						currentTableSize = 0;
						ReportError(u8"In WinDiverter::GetPacketProcess(uint16_t, uint32_t[4], PMIB_TCP6TABLE2, DWORD&) - Failed to initialize table.");
						return 0;
					}

					DWORD dwRetVal = 0;

					if ((dwRetVal = GetTcp6Table2(*table, &currentTableSize, FALSE)) == ERROR_INSUFFICIENT_BUFFER)
					{
						free(*table);
						*table = nullptr;

						*table = static_cast<PMIB_TCP6TABLE2>(malloc(currentTableSize));

						if (table == nullptr)
						{
							currentTableSize = 0;
							ReportError(u8"In WinDiverter::GetPacketProcess(uint16_t, uint32_t[4], PMIB_TCP6TABLE2, DWORD&) - Failed to resize table.");
							return 0;
						}

						dwRetVal = GetTcp6Table2(*table, &currentTableSize, FALSE);
					}

					uint64_t p1 = ((static_cast<uint64_t>(localV6Address[0]) << 32) | (localV6Address[1]));
					uint64_t p2 = ((static_cast<uint64_t>(localV6Address[2]) << 32) | (localV6Address[3]));

					if (dwRetVal == NO_ERROR)
					{
						// Table members, spare things like dwOwningPid, are in network order aka big endian.
						for (DWORD i = 0; i < (*table)->dwNumEntries; ++i)
						{
							uint64_t pp1 = (
								(static_cast<uint64_t>((*table)->table[i].LocalAddr.u.Word[0]) << 48) |
								(static_cast<uint64_t>((*table)->table[i].LocalAddr.u.Word[1]) << 32) |
								(static_cast<uint64_t>((*table)->table[i].LocalAddr.u.Word[2]) << 16) |
								(static_cast<uint64_t>((*table)->table[i].LocalAddr.u.Word[3]))
								);

							uint64_t pp2 = (
								(static_cast<uint64_t>((*table)->table[i].LocalAddr.u.Word[4]) << 48) |
								(static_cast<uint64_t>((*table)->table[i].LocalAddr.u.Word[5]) << 32) |
								(static_cast<uint64_t>((*table)->table[i].LocalAddr.u.Word[6]) << 16) |
								(static_cast<uint64_t>((*table)->table[i].LocalAddr.u.Word[7]))
								);

							// The reason why we accept zero as the address is that it is equal to "[::]:PORT", so
							// it counts.
							if ((pp1 == 0 && pp2 == 0) || (pp1 == p1 && pp2 == p2))
							{
								// See https://msdn.microsoft.com/en-us/library/windows/desktop/aa366909(v=vs.85).aspx
								// Upper bits may contain junk data.
								if (((*table)->table[i].dwLocalPort & 0xFFFF) == localPort)
								{
									return (*table)->table[i].dwOwningPid;
								}
							}
						}
					}
					else
					{
						ReportError(u8"In WinDiverter::GetPacketProcess(uint16_t, uint32_t[4], PMIB_TCP6TABLE2, DWORD&) - Failed to populate table.");

						if (*table != nullptr)
						{
							free(*table);
							*table = nullptr;
						}

						currentTableSize = 0;
					}

					return 0;
				}
			} /* namespace diversion */
		}/* namespace mitm */
	}/* namespace httpengine */
}/* namespace te */