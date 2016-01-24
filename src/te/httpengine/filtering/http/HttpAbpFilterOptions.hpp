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

#include <bitset>
#include <cstdint>

namespace te
{
	namespace httpengine
	{
		namespace filtering
		{
			namespace http
			{

				/// <summary>
				/// Each ABP Filter can specify many details about just what type of requests and
				/// content a filter ought to apply to. By configuring these options, it's possible to
				/// develop filters that will return a match against images, but not against scripts, or
				/// against third-party CSS Documents, etc. This enum serves as convenient key system
				/// for checking and setting options on the HttpAbpFilterSettings object, a fixed-size
				/// bitset where any of these options, by the corresponding enum key, can be
				/// manipulated.
				/// </summary>
				enum HttpAbpFilterOption
					: size_t
				{
					script = 0,
					notscript = 1,
					image = 2,
					notimage = 3,
					stylesheet = 4,
					notstylesheet = 5,
					object = 6,
					notobject = 7,
					object_subrequest = 8,
					notobject_subrequest = 9,
					subdocument = 10,
					notsubdocument = 11,
					document = 12,
					notdocument = 13,
					elemhide = 14,
					notelemhide = 15,
					third_party = 16,
					notthird_party = 17,
					xmlhttprequest = 18,
					notxmlhttprequest = 19
				};

				typedef std::bitset<20> HttpAbpFilterSettings;

			} /* namespace http */
		} /* namespace filtering */
	} /* namespace httpengine */
} /* namespace te */