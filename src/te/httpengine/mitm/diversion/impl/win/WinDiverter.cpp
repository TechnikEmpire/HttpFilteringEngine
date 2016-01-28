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
						throw new std::runtime_error(u8"In WinDiverter::WinDiverter(...) - No valid firewall check callback was supplied.");
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

						m_diversionHandle = WinDivertOpen(u8"outbound and tcp and (ip.DstAddr != 127.0.0.1 and ip.SrcAddr != 127.0.0.1)", WINDIVERT_LAYER_NETWORK, -1000, WINDIVERT_FLAG_NO_CHECKSUM);

						if (m_diversionHandle == INVALID_HANDLE_VALUE)
						{
							std::string errMessage("In WinDiverter::Run() - Failed to start Diversion, got invalid WinDivert handle with error:\n\t");
							errMessage.append(std::to_string(GetLastError()));

							throw new std::runtime_error(errMessage.c_str());
						}

						WinDivertSetParam(m_diversionHandle, WINDIVERT_PARAM_QUEUE_LEN, 8192);

						WinDivertSetParam(m_diversionHandle, WINDIVERT_PARAM_QUEUE_TIME, 2048);

						auto numLogicalCores = std::thread::hardware_concurrency();

						// XXX TODO - Magic number, arbitrary number for deciding threads. Need an option to
						// allow users to configure number of threads used for diversion.
						for (unsigned int i = 0; i < numLogicalCores * 3; ++i)
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

						if (m_diversionHandle != nullptr)
						{
							WinDivertClose(m_diversionHandle);
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
					m_buffer.reset(new PacketBuffer());

					uint32_t recvLength = 0;

					PWINDIVERT_IPHDR ipV4Header = nullptr;
					PWINDIVERT_IPV6HDR ipV6Header = nullptr;
					PWINDIVERT_TCPHDR tcpHeader = nullptr;

					PMIB_TCPTABLE2 ipv4TcpTable = nullptr;
					DWORD ipv4TcpTableSize = 0;

					PMIB_TCP6TABLE2 ipv6TcpTable = nullptr;
					DWORD ipv6TcpTableSize = 0;					

					#ifdef HTTP_FILTERING_ENGINE_USE_EX
						OVERLAPPED recvOverlapped;
						HANDLE recvEvent = nullptr;
						DWORD recvAsyncIoLen;
					#endif

					// Rather than creating a structures to be shared across all thread that track
					// which apps have firewall permissions, we simple create one per-thread. We waste
					// a little bit of space, but we avoid the headaches of synchronization. Note 
					// however that this convenience will have to go once we implement things like
					// port independent protocol mapping, and proper flow tracking, which is needed
					// to ensure we supply filtering to traffic other than port 80 and 443.					
					
					// So presently, rather than doing proper flow tracking and such, we kind of just do
					// a dirty little hack. We keep track of "flows" only by destination local port, then
					// every couple of seconds we re-check the process ID bound to the port to make sure
					// that we're still serving a process other than our own. Plus, we also make sure we're
					// still serving the same process that we got the binary name of, checked the firewall
					// status of etc, before caching it here.
					//
					// The benefit here is that we don't have to keep hammering the kernel for TCP and TCP6 tables
					// which contain process information about ports, just to avoid accidently intercepting our
					// own traffic. Just by caching for a second or two, we cut CPU usage down to nil. Without
					// it, you'll see the CPU get eaten alive while streaming video or something.
					std::unordered_map<uint16_t, ProcessNfo> tcpPidLastCheck;

					while (m_running)
					{
						recvLength = 0;
						memset(&addr, 0, sizeof(addr));

						// WinDivert has a recv and send overload that uses overlapped IO to provide nonblocking
						// recv and send functions that can be manually waited and timed out. These overloads
						// have an "ex" suffix. 
						//
						// Enabling this is optional at compile time. While I much prefer the idea of being able
						// to guarantee a thread is never going to be chocking indefinitely on a recv, I've 
						// experienced... unstable results using the recvex function.
						#ifdef HTTP_FILTERING_ENGINE_USE_EX

							recvAsyncIoLen = 0;
							memset(&recvOverlapped, 0, sizeof(OVERLAPPED));
							recvEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

							if (recvEvent == nullptr)
							{
								std::string errMessage("In WinDiverter::RunDiversion(LPVOID) - While creating RecvEx event, got error:\n\t");
								errMessage.append(std::to_string(GetLastError()));
								ReportError(errMessage);
								continue;
							}

							recvOverlapped.hEvent = recvEvent;

							if (!WinDivertRecvEx(divertHandle, m_buffer.get(), PacketBufferLength, 0, &addr, &recvLength, &recvOverlapped))
							{
								auto err = GetLastError();
								if (err != ERROR_IO_PENDING)
								{
									std::string errMessage("In WinDiverter::RunDiversion(LPVOID) - During call to WinDivert RecvEx, got error:\n\t");
									errMessage.append(std::to_string(err));
									ReportError(errMessage);
									continue;
								}

								// XXX TODO - Had to set this timeout VERY high when I was diverting
								// DNS once upon a time, perhaps this isn't the case since we're
								// sticking to TCP. Never figured out why I had to do this in the
								// first place.
								auto result = WaitForSingleObject(recvEvent, 5000);

								if (result != WAIT_OBJECT_0)
								{
									if (result == WAIT_TIMEOUT)
									{
										ReportError(u8"In WinDiverter::RunDiversion(LPVOID) - Call to WinDivert RecvEx timed out.");
									}
									else
									{
										std::string errMessage("In WinDiverter::RunDiversion(LPVOID) - During call to WinDivert RecvEx, got error:\n\t");
										errMessage.append(std::to_string(GetLastError()));
										ReportError(errMessage);
									}

									CloseHandle(recvEvent);
									continue;
								}

								if (!GetOverlappedResult(divertHandle, &recvOverlapped, &recvAsyncIoLen, TRUE))
								{
									std::string errMessage("In WinDiverter::RunDiversion(LPVOID) - During call to WinDivert RecvEx, while fetching overlapped result, got error:\n\t");
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

							if (!WinDivertRecv(divertHandle, m_buffer.get(), PacketBufferLength, &addr, &recvLength))
							{
								std::string errMessage("In WinDiverter::RunDiversion(LPVOID) - During call to WinDivert Recv, got error:\n\t");
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
							WinDivertHelperParsePacket(m_buffer.get(), recvLength, &ipV4Header, &ipV6Header, nullptr, nullptr, &tcpHeader, nullptr, nullptr, nullptr);
							
							// I put the checks for ipv4 and ipv6 as a double if statement rather
							// than an else if because I'm not sure how that would affect dual-mode
							// sockets. Perhaps it's possible for both headers to be defined.
							// Probably not, but since I don't know, I err on the side of awesome,
							// or uhh, something like that.

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
								else if(tcpHeader->DstPort == StandardHttpPort || tcpHeader->DstPort == StandardHttpsPort)
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
									//
									// Then, whatever the results, if it wasn't cached, we'll cache it for a short
									// period of time.

									const auto& cached = tcpPidLastCheck.find(tcpHeader->SrcPort);
									auto now = std::chrono::high_resolution_clock::now();

									bool hasFirewallAccess = false;

									unsigned long procPid = 0;

									if (cached != tcpPidLastCheck.end() && (std::get<2>(cached->second) > now))
									{
										procPid = std::get<0>(cached->second);
									}
									else
									{
										procPid = GetPacketProcess(tcpHeader->SrcPort, ipV4Header->SrcAddr, &ipv4TcpTable, ipv4TcpTableSize);
									}

									now += std::chrono::duration_cast<std::chrono::high_resolution_clock::duration>(std::chrono::seconds(3));

									// So we make sure that this packet doesn't belong to us (the proxy), we make sure that we also got a valid
									// process (non-zero) and also that the process isn't a protected operating system process (pid 4). If
									// all these things pass, then we want to divert this packet to the proxy.
									if (procPid != m_thisPid && procPid != 0 && procPid != 4)
									{
										auto processName = GetPacketProcessBinaryPath(procPid);

										if (processName.size() > 0)
										{
											hasFirewallAccess = m_firewallCheckCb(processName.c_str(), processName.size());

											tcpPidLastCheck[tcpHeader->SrcPort] = ProcessNfo{ procPid, hasFirewallAccess, now };
										}

										if (hasFirewallAccess)
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
							}
							
							// The ipV6 version works exactly the same, just with larger storage for the larger
							// addresses. Look at the ipv4 version notes for clarification on anything.
							if (ipV6Header != nullptr && tcpHeader != nullptr)
							{
								if (tcpHeader->SrcPort == m_httpListenerPort || tcpHeader->SrcPort == m_httpsListenerPort)
								{
									uint32_t dstAddr[4];

									std::copy(ipV6Header->DstAddr, ipV6Header->DstAddr + 4, dstAddr);	
									std::copy(ipV6Header->SrcAddr, ipV6Header->SrcAddr + 4, ipV6Header->DstAddr);
									std::copy(dstAddr, dstAddr + 4, ipV6Header->SrcAddr);

									tcpHeader->SrcPort = (tcpHeader->SrcPort == m_httpListenerPort) ? StandardHttpPort : StandardHttpsPort;

									addr.Direction = WINDIVERT_DIRECTION_INBOUND;
								}
								else if (tcpHeader->DstPort == StandardHttpPort || tcpHeader->DstPort == StandardHttpsPort)
								{

									const auto& cached = tcpPidLastCheck.find(tcpHeader->SrcPort);
									auto now = std::chrono::high_resolution_clock::now();

									bool hasFirewallAccess = false;

									unsigned long procPid = 0;

									if (cached != tcpPidLastCheck.end() && (std::get<2>(cached->second) > now))
									{
										procPid = std::get<0>(cached->second);
									}
									else
									{
										procPid = GetPacketProcess(tcpHeader->SrcPort, ipV6Header->SrcAddr, &ipv6TcpTable, ipv6TcpTableSize);
									}

									now += std::chrono::duration_cast<std::chrono::high_resolution_clock::duration>(std::chrono::seconds(3));

									if (procPid != m_thisPid && procPid != 0 && procPid != 4)
									{
										auto processName = GetPacketProcessBinaryPath(procPid);

										if (processName.size() > 0)
										{
											hasFirewallAccess = m_firewallCheckCb(processName.c_str(), processName.size());

											tcpPidLastCheck[tcpHeader->SrcPort] = ProcessNfo{ procPid, hasFirewallAccess, now };
										}

										if (hasFirewallAccess)
										{
											uint32_t dstAddr[4];

											std::copy(ipV6Header->DstAddr, ipV6Header->DstAddr + 4, dstAddr);
											std::copy(ipV6Header->SrcAddr, ipV6Header->SrcAddr + 4, ipV6Header->DstAddr);
											std::copy(dstAddr, dstAddr + 4, ipV6Header->SrcAddr);

											addr.Direction = WINDIVERT_DIRECTION_INBOUND;

											tcpHeader->DstPort = (tcpHeader->DstPort == StandardHttpPort) ? m_httpListenerPort : m_httpsListenerPort;
										}
									}
								}
							}
						} // if (addr.Direction == WINDIVERT_DIRECTION_OUTBOUND)

						WinDivertHelperCalcChecksums(m_buffer.get(), recvLength, 0);

						if (!WinDivertSendEx(divertHandle, m_buffer.get(), recvLength, 0, &addr, nullptr, nullptr))
						{
							// XXX TODO - Perhaps report warning instead? This isn't exactly critical. Maybe a single
							// packet gets lost, maybe it completes under the hood. Either way we can do nothing, and
							// this should be expected to happen at least once.
							std::string errMessage("In WinDiverter::RunDiversion(LPVOID) - During call to WinDivert SendEx, got error:\n\t");
							errMessage.append(std::to_string(GetLastError()));
							ReportError(errMessage);
							continue;
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
					HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);

					if (processHandle != nullptr && processHandle != INVALID_HANDLE_VALUE)
					{
						DWORD resSize = MAX_PATH;
						char filename[MAX_PATH];
						
						if (QueryFullProcessImageNameA(processHandle, 0, filename, &resSize) == 0)
						{
							ReportError(u8"In WinDiverter::GetPacketProcess(const unsigned long) - Failed to get binary path.");
							CloseHandle(processHandle);
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
						ReportError(u8"In WinDiverter::GetPacketProcess(const unsigned long) - Failed to open process to query binary path.");
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
							if ((*table)->table[i].dwLocalAddr == 0 || (*table)->table[i].dwLocalAddr == localV4Address)
							{
								if ((*table)->table[i].dwLocalPort == localPort)
								{
									return (*table)->table[i].dwOwningPid;
								}
							}
						}
					}
					else
					{
						ReportError(u8"In WinDiverter::GetPacketProcess(uint16_t, uint32_t, PMIB_TCPTABLE2, DWORD&) - Failed to populate table.");
					}

					return 0;
				}

				DWORD WinDiverter::GetPacketProcess(uint16_t localPort, uint32_t* localV6Address, PMIB_TCP6TABLE2* table, DWORD& currentTableSize)
				{
					// We deliberately never permanently free the table on purpose. Eventually, this table will
					// reach a size where reallocations don't happen anymore, and we can recycle it.

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
								if ((*table)->table[i].dwLocalPort == localPort)
								{
									return (*table)->table[i].dwOwningPid;
								}
							}
						}
					}
					else
					{
						ReportError(u8"In WinDiverter::GetPacketProcess(uint16_t, uint32_t[4], PMIB_TCP6TABLE2, DWORD&) - Failed to populate table.");
					}

					return 0;
				}

			} /* namespace diversion */
		}/* namespace mitm */
	}/* namespace httpengine */
}/* namespace te */

