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

#include "../../BaseDiverter.hpp"

#include <cstdint>
#include <mutex>
#include <thread>
#include <vector>
#include <array>
#include <tuple>
#include <chrono>

#include <WS2tcpip.h>
#include <ws2def.h>
#include <ws2ipdef.h>
#include <Iphlpapi.h>
#include <tcpmib.h>
#include <udpmib.h>
#include <psapi.h>

#include <windivert.h>

namespace te
{
	namespace httpengine
	{
		namespace mitm
		{
			namespace diversion
			{

				/// <summary>
				/// The WinDiverter class provides a packet diversion mechanism specialized for use
				/// on Windows systems, supporting Vista and later. The WinDiverter class is powered
				/// by the excellent WinDivert kernel driver, which is built upon the Windows
				/// Filtering Platform.
				/// </summary>
				class WinDiverter : public BaseDiverter
				{

					friend class DiversionControl;

				public:		

					/// <summary>
					/// Default destructor.
					/// </summary>
					virtual ~WinDiverter();
					
					/// <summary>
					/// Gets the port number that the diverter is configured to sent identified HTTP
					/// flows to.
					/// 
					/// Overridden to ensure that this interface accepts and returns the port number
					/// in host order aka little endian. However, internally these values are stored
					/// in network order, aka big endian. The underlying conversion mechanism gives
					/// us raw packet headers, and rather than calling ntohs and htons on each
					/// diversion loop, we provide the conversion once, and on demand from the user.
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
					/// 
					/// Overridden to ensure that this interface accepts and returns the port number
					/// in host order aka little endian. However, internally these values are stored
					/// in network order, aka big endian. The underlying conversion mechanism gives
					/// us raw packet headers, and rather than calling ntohs and htons on each
					/// diversion loop, we provide the conversion once, and on demand from the user.
					/// </summary>
					/// <param name="port">
					/// The port number that the diverter is to sent identified HTTP flows to.
					/// </param>
					virtual void SetHttpListenerPort(const uint16_t port);

					/// <summary>
					/// Gets the port number that the diverter is configured to sent identified
					/// HTTPS flows to.
					/// 
					/// Overridden to ensure that this interface accepts and returns the port number
					/// in host order aka little endian. However, internally these values are stored
					/// in network order, aka big endian. The underlying conversion mechanism gives
					/// us raw packet headers, and rather than calling ntohs and htons on each
					/// diversion loop, we provide the conversion once, and on demand from the user.
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
					/// 
					/// Overridden to ensure that this interface accepts and returns the port number
					/// in host order aka little endian. However, internally these values are stored
					/// in network order, aka big endian. The underlying conversion mechanism gives
					/// us raw packet headers, and rather than calling ntohs and htons on each
					/// diversion loop, we provide the conversion once, and on demand from the user.
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
					virtual void Run();

					/// <summary>
					/// Stops the packet diversion process.
					/// </summary>
					virtual void Stop();

					/// <summary>
					/// Indicates whether or not the packet diversion process is presently active.
					/// </summary>
					/// <returns>
					/// True if the packet diversion process is presently active, false otherwise.
					/// </returns>
					virtual const bool IsRunning() const;

				protected:

					/// <summary>
					/// Constructs a new WinDiverter used for diverting network traffic on Windows
					/// Vista and later. This constructor should be expected to throw a
					/// std::runtime_error in the event that invalid arguments are supplied. For
					/// example, as the firewallCheckCb is required for this platform, providing an
					/// invalid function here will result in a throw.
					/// </summary>
					/// <param name="firewallCheckCb">
					/// Callback that the underlying packet diversion mechanism can use to verify
					/// that traffic intercepted from specific machine local binaries is permitted
					/// to be sent outbound from the device. Required.
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
					WinDiverter(
						util::cb::FirewallCheckFunction firewallCheckCb,
						util::cb::MessageFunction onInfo = nullptr,
						util::cb::MessageFunction onWarning = nullptr,
						util::cb::MessageFunction onError = nullptr
						);

					/// <summary>
					/// The size of the packet read buffer.
					/// </summary>
					static constexpr uint32_t PacketBufferLength = 65535;

					/// <summary>
					/// Standard HTTP port, aka port 80. Stored in network order aka big endian so
					/// that no conversion is required in equality tests.
					/// </summary>
					static const uint32_t StandardHttpPort;

					/// <summary>
					/// Standard HTTPS port, aka port 443. Stored in network order aka big endian so
					/// that no conversion is required in equality tests.
					/// </summary>
					static const uint32_t StandardHttpsPort;

					/// <summary>
					/// Stores our own process ID, so that we do not interfere with our network traffic.
					/// </summary>
					DWORD m_thisPid = 0;

					/// <summary>
					/// The WinDivert driver supplied handle by which we divert packets.
					/// </summary>
					HANDLE m_diversionHandle = nullptr;

					/// <summary>
					/// For synchronization during ::Run()/::Stop() calls.
					/// </summary>
					std::mutex m_startStopMutex;
					
					/// <summary>
					/// Stores all threads that are given the task of using a supplied WinDivert
					/// handle to divert traffic.
					/// </summary>
					std::vector<std::thread> m_diversionThreads;					

					using PacketBuffer = std::array<unsigned char, PacketBufferLength>;
					using ProcessNfo = std::tuple<unsigned long, bool, std::chrono::high_resolution_clock::time_point>;

					/// <summary>
					/// The packet read buffer.
					/// </summary>
					std::unique_ptr < PacketBuffer > m_buffer;

					/// <summary>
					/// This method is the one that generated threads for running the diversion
					/// invoke. This is where all the work is really done.
					/// </summary>
					/// <param name="diversionHandlePtr">
					/// A valid WinDivert handle.
					/// </param>
					void RunDiversion(LPVOID diversionHandlePtr);

					/// <summary>
					/// Attempts to get limited read permission for the process identified by the
					/// supplied process ID, then attempts to read the full path of the binary
					/// latched to the process ID and return it.
					/// </summary>
					/// <param name="processId">
					/// The process to attempt to read.
					/// </param>
					/// <returns>
					/// A string with a ::size() greater than zero if the process image name, aka
					/// the full path of the executable latched to the process ID, was successfully
					/// read. A string with a ::size() of zero if the read failed.
					/// </returns>
					std::string GetPacketProcessBinaryPath(const unsigned long processId) const;

					/// <summary>
					/// Given the supplied port, ip address and table information, attempts to
					/// return the process ID for the process bound to the supplied port and
					/// address.
					/// </summary>
					/// <param name="localPort">
					/// The port number to be used to determine the process ID for the machine local
					/// binary bound to the supplied port, if it's in use.
					/// </param>
					/// <param name="localV4Address">
					/// The address of the interface to be used to determine the process ID for the
					/// machine local binary bound to the supplied port, if it's in use.
					/// </param>
					/// <param name="table">
					/// A pointer to a pointer of a MIB_TCPTABLE2 structure to be allocated,
					/// reallocated (resizing), and used for fetching the TCP table from the kernel.
					/// This object can and will be reallocated to accomodate entries that exceed
					/// the present storage capacity. The currentTableSize parameter will be updated
					/// if the table is resized.
					/// </param>
					/// <param name="currentTableSize">
					/// The current size allocated to the supplied MIB_TCPTABLE2 structure. Will be
					/// updated in the event that the supplied MIB_TCPTABLE2 structure is resized.
					/// </param>
					/// <returns>
					/// A non-zero value if a process was found bound to the interface address and
					/// port combination. A value of zero otherwise. A value of four indicates that
					/// a protected operating system process has control of the port.
					/// </returns>
					DWORD GetPacketProcess(uint16_t localPort, uint32_t localV4Address, PMIB_TCPTABLE2* table, DWORD& currentTableSize);

					/// <summary>
					/// Given the supplied port, ip address and table information, attempts to
					/// return the process ID for the process bound to the supplied port and
					/// address.
					/// </summary>
					/// <param name="localPort">
					/// The port number to be used to determine the process ID for the machine local
					/// binary bound to the supplied port, if it's in use.
					/// </param>
					/// <param name="localV6Address">
					/// The address of the interface to be used to determine the process ID for the
					/// machine local binary bound to the supplied port, if it's in use. In this
					/// case, this is represented by an array of 32 bit unsigned integers with a
					/// length of four. No bounds checks are done. Burden is on the user to pass
					/// correct data.
					/// </param>
					/// <param name="table">
					/// A pointer to a pointer of a MIB_TCP6TABLE2 structure to be allocated,
					/// reallocated (resizing), and used for fetching the TCP table from the kernel.
					/// This object can and will be reallocated to accomodate entries that exceed
					/// the present storage capacity. The currentTableSize parameter will be updated
					/// if the table is resized.
					/// </param>
					/// <param name="currentTableSize">
					/// The current size allocated to the supplied MIB_TCP6TABLE2 structure. Will be
					/// updated in the event that the supplied MIB_TCP6TABLE2 structure is resized.
					/// </param>
					/// <returns>
					/// A non-zero value if a process was found bound to the interface address and
					/// port combination. A value of zero otherwise. A value of four indicates that
					/// a protected operating system process has control of the port.
					/// </returns>
					DWORD GetPacketProcess(uint16_t localPort, uint32_t* localV6Address, PMIB_TCP6TABLE2* table, DWORD& currentTableSize);

				};

			} /* namespace diversion */
		}/* namespace mitm */
	}/* namespace httpengine */
}/* namespace te */

