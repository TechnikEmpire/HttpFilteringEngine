/*
* Copyright © 2017 Jesse Nicholson
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
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
