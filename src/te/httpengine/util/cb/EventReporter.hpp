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

#include <boost/signals2.hpp>
#include <string>
#include <functional>

namespace te
{
	namespace httpengine
	{
		namespace util
		{
			namespace cb
			{

				/// <summary>
				/// The EventReporter class is meant to serve as a semi generic class for reporting
				/// general information, warnings and errors to one or more unknown observers. We
				/// don't care who is listening and thanks to boost::signals2 we have a nice measure
				/// of decoupling here. The fact is one or more parties may be interested in
				/// observing such output from arbitrary objects, and portions of this software
				/// definitely are interested, we just don't want to be bound to them.
				/// 
				/// The original intention of this templated class was to allow any class to, in a
				/// variably generic fashion, equip itself with the ability to give information or
				/// instruction in a command pattern fashion. This class however, is presently
				/// under-developed, and lacking, but is left included and used for the sole purpose
				/// of having one-way messaging system between objects and interested observers. For
				/// this purpose, it's overkill and could be replaced by a simple std::function.
				/// 
				/// Much of the library operates entirely independently of any outside interaction,
				/// in fact in much of it, there is little that a third party (such as an
				/// implementing UI application) can do but turn it on and observe. There does exist
				/// an interface where functionality can be modified, but I'm speaking more from the
				/// perspective of a programmer as a consumer. It's not acceptable for much of the
				/// functionality of this library to stop and throw an unhandled error, because the
				/// nature of the functionality is dealing entirely with unknown external input. So
				/// the library handles most foreseeable issues itself safely, but without a
				/// reporting interface like this, it would be entirely a blackbox to a programmer 
				/// consumer.
				/// </summary>
				template <class... ParamTypes>
				class EventReporter
				{

				public:

					/// <summary>
					/// Function definition that accepts a string and unsigned 32 bit integer code
					/// describing an event.
					/// </summary>
					using StringAndCodeFunction = std::function<void(const std::string&, const uint32_t&)>;

					/// <summary>
					/// Signal definition for StringAndCodeFunction callbacks.
					/// </summary>
					using StringAndCodeSignal = boost::signals2::signal<void(const std::string&, const uint32_t&)>;

					/// <summary>
					/// Function definition that accepts a string and unsigned 32 bit integer code
					/// describing an event.
					/// </summary>
					using DataFunction = typename std::function<void(ParamTypes...)>;

					/// <summary>
					/// Signal definition for DataFunction callbacks.
					/// </summary>
					using DataSignal = typename boost::signals2::signal<void(ParamTypes...)>;
					
					EventReporter()
					{

					}

					virtual ~EventReporter()
					{

					}

					/// <summary>
					/// Subscribe to the information event. This event will be raised when general
					/// information which is considered potentially useful is raised, such as a
					/// notification that a task has completed.
					/// </summary>
					/// <param name="callback">
					/// The callback function where information events should be dispatched to. 
					/// </param>
					/// <returns>
					/// The slot for the newly registered callback. This must be retained to
					/// unsubscribe.
					/// </returns>
					boost::signals2::connection SubscribeOnInfo(StringAndCodeFunction callback)
					{						
						return m_infoSignal.connect(callback);
					}

					/// <summary>
					/// Subscribe to the warning event. This event will be raised when information
					/// is generated about a potential low severity event.
					/// </summary>
					/// <param name="callback">
					/// The callback function where warning events should be dispatched to. 
					/// </param>
					/// <returns>
					/// The slot for the newly registered callback. This must be retained to
					/// unsubscribe.
					/// </returns>
					boost::signals2::connection SubscribeOnWarning(StringAndCodeFunction callback)
					{
						m_warningSignal.connect(callback);
					}

					/// <summary>
					/// Subscribe to the error event. This event will be raised when information is
					/// generated about a potentially serious event that was caught and handled.
					/// </summary>
					/// <param name="callback">
					/// The callback function where error events should be dispatched to. 
					/// </param>
					/// <returns>
					/// The slot for the newly registered callback. This must be retained to
					/// unsubscribe.
					/// </returns>
					boost::signals2::connection SubscribeOnError(StringAndCodeFunction callback)
					{
						m_errorSignal.connect(callback);
					}

					/// <summary>
					/// The data event. This event will be raised when data about an event is being
					/// made available to potential observers. This additional data parameter is
					/// templated so implementers may provide different data, if at all. Check the
					/// summary comments on the inheriting class for details about what data the
					/// class intends to dispatch through this event, if anything.
					/// </summary>
					/// <param name="callback">
					/// The callback function where data events should be dispatched to. 
					/// </param>
					/// <returns>
					/// The slot for the newly registered callback. This must be retained to
					/// unsubscribe.
					/// </returns>
					boost::signals2::connection SubscribeOnData(DataFunction callback)
					{
						m_dataSignal.connect(callback);
					}

				protected:

					/// <summary>
					/// Subclasses can report general information through this function. 
					/// </summary>
					/// <param name="message">
					/// A string message containing meaningful information about an event. 
					/// </param>
					/// <param name="code">
					/// A code associated with this event. This interface is agnostic to user
					/// created codes and meanings, except that they are expected as a 32 bit
					/// unsigned integer.
					/// </param>
					void ReportInfo(const std::string& message, const uint32_t code = 0) const
					{
						m_infoSignal(message, code);
					}

					/// <summary>
					/// Subclasses can report warning information through this function. 
					/// </summary>
					/// <param name="message">
					/// A string message containing meaningful information about an event. 
					/// </param>
					/// <param name="code">
					/// A code associated with this event. This interface is agnostic to user
					/// created codes and meanings, except that they are expected as a 32 bit
					/// unsigned integer.
					/// </param>
					void ReportWarning(const std::string& message, const uint32_t code = 0) const
					{
						m_warningSignal(message, code);
					}

					/// <summary>
					/// Subclasses can report error information through this function. 
					/// </summary>
					/// <param name="message">
					/// A string message containing meaningful information about an event. 
					/// </param>
					/// <param name="code">
					/// A code associated with this event. This interface is agnostic to user
					/// created codes and meanings, except that they are expected as a 32 bit
					/// unsigned integer.
					/// </param>
					void ReportError(const std::string& message, const uint32_t code = 0) const
					{
						m_errorSignal(message, code);
					}

					/// <summary>
					/// Subclasses can report data information through this function. The method is
					/// marked virtual so that subclasses may override. This may be useful in a
					/// situation where a subclass defines the template types to be non-const
					/// references or pointers, offering data out for manipulation rather than just
					/// pure observation.
					/// </summary>
					/// <param name="message">
					/// A string message containing meaningful information about an event. 
					/// </param>
					/// <param name="code">
					/// A code associated with this event. This interface is agnostic to user
					/// created codes and meanings, except that they are expected as a 32 bit
					/// unsigned integer.
					/// </param>
					/// <param name="data">
					/// Templated data type object to be provided in the callback as a const
					/// reference.
					/// </param>
					virtual void ReportData(ParamTypes... params) const
					{
						m_dataSignal(std::forward<ParamTypes>(params)...);
					}

				private:

					StringAndCodeSignal m_infoSignal;

					StringAndCodeSignal m_warningSignal;

					StringAndCodeSignal m_errorSignal;

					DataSignal m_dataSignal;

				};

			} /* namespace cb */
		} /* namespace util */
	} /* namespace httpengine */
} /* namespace te */