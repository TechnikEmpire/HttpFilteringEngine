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

#include "EngineCallbackTypes.h"
#include <boost/utility/string_ref.hpp>
#include <thread>

namespace te
{
	namespace httpengine
	{
		namespace util
		{
			namespace cb
			{

				/// <summary>
				/// The EventReporter is a simple class meant to contain pointers to functions
				/// designed for various purposes, and providing a simply interface to access these
				/// functions. This class is simply included for convenience and to reduce code
				/// duplication, as more than one class in this library attempts to provide
				/// informational callbacks to users for handled events.
				/// 
				/// The methods for setting functions and invoke them are marked virtual to allow
				/// the possibility of implementations where these methods are given thread safety
				/// and such, while keeping this basic class basic and free of any such additional 
				/// overhead.
				/// </summary>
				class EventReporter
				{

				public:

					/// <summary>
					/// Constructs members with the given arguments. Nothing special here.
					/// </summary>
					/// <param name="onInfo">
					/// Callback for general information about non-critical events.
					/// </param>
					/// <param name="onWarning">
					/// Callback for warnings about potentially critical events.
					/// </param>
					/// <param name="onError">
					/// Callback for error information about critical events that were handled.
					/// </param>
					EventReporter(
						MessageFunction onInfo = nullptr,
						MessageFunction onWarning = nullptr,
						MessageFunction onError = nullptr
						) :
						m_onInfo(onInfo),
						m_onWarning(onWarning),
						m_onError(onError)
					{

					}

					/// <summary>
					/// Default destructor.
					/// </summary>
					virtual ~EventReporter()
					{

					}

					/// <summary>
					/// Sets the callback for general information about non-critical events.
					/// </summary>
					/// <param name="onInfo">
					/// Callback for general information about non-critical events.
					/// </param>
					virtual void SetOnInfo(MessageFunction onInfo)
					{
						m_onInfo = onInfo;
					}

					/// <summary>
					/// Sets the callback for warnings about potentially critical events.
					/// </summary>
					/// <param name="onWarning">
					/// Callback for warnings about potentially critical events.
					/// </param>
					virtual void SetOnWarning(MessageFunction onWarning)
					{
						m_onWarning = onWarning;
					}

					/// <summary>
					/// Sets the callback for error information about critical events that were handled.
					/// </summary>
					/// <param name="onError">
					/// Callback for error information about critical events that were handled.
					/// </param>
					virtual void SetOnError(MessageFunction onError)
					{
						m_onError = onError;
					}

					/// <summary>
					/// If the info callback member is valid, invokes it with the informational
					/// message data as arguments.
					/// </summary>
					/// <param name="infoMessage">
					/// An informational string about a non-critical event.
					/// </param>
					virtual void ReportInfo(const boost::string_ref infoMessage) const
					{
						if (m_onInfo && infoMessage.data())
						{
							#ifndef NDEBUG
								std::string m = u8"From Thread " + std::to_string(std::hash<std::thread::id>()(std::this_thread::get_id()));
								m.append(": ").append(infoMessage.to_string());
								m_onInfo(m.c_str(), m.size());
							#else
								m_onInfo(infoMessage.begin(), infoMessage.size());
							#endif
						}
					}

					/// <summary>
					/// If the warning callback member is valid, invokes it with the warning message
					/// data as arguments.
					/// </summary>
					/// <param name="warningMessage">
					/// An informational string about potentially critical event.
					/// </param>
					virtual void ReportWarning(const boost::string_ref warningMessage) const
					{
						if (m_onWarning && warningMessage.data())
						{
							#ifndef NDEBUG
								std::string m = u8"From Thread " + std::to_string(std::hash<std::thread::id>()(std::this_thread::get_id()));
								m.append(": ").append(warningMessage.to_string());
								m_onWarning(m.c_str(), m.size());
							#else
								m_onWarning(warningMessage.begin(), warningMessage.size());
							#endif							
						}
					}

					/// <summary>
					/// If the error callback member is valid, invokes it with the error message
					/// data as arguments.
					/// </summary>
					/// <param name="errorMessage">
					/// An informational string about a critical event.
					/// </param>
					virtual void ReportError(const boost::string_ref errorMessage) const
					{
						if (m_onError && errorMessage.data())
						{
							#ifndef NDEBUG
								std::string m = u8"From Thread " + std::to_string(std::hash<std::thread::id>()(std::this_thread::get_id()));
								m.append(": ").append(errorMessage.to_string());
								m_onError(m.c_str(), m.size());
							#else
								m_onError(errorMessage.begin(), errorMessage.size());
							#endif
						}
					}

					// XXX TODO - I changed this to protected so that those who inherit can simply
					// pass copies of their own callbacks around. I did this because... this class
					// was designed without any planning. So todo is to make this not quite so dirty.
				protected:

					/// <summary>
					/// Callback for general information about non-critical events.
					/// </summary>
					MessageFunction m_onInfo;

					/// <summary>
					/// Callback for warnings about potentially critical events.
					/// </summary>
					MessageFunction m_onWarning;

					/// <summary>
					/// Callback for error information about critical events that were handled.
					/// </summary>
					MessageFunction m_onError;

				};

			} /* namespace cb */
		} /* namespace util */
	} /* namespace httpengine */
} /* namespace te */
