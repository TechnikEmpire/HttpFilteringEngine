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

#include "HttpAbpBaseFilter.hpp"

namespace te
{
	namespace httpengine
	{
		namespace filtering
		{
			namespace http
			{

				class HttpAbpInclusionFilter : public HttpAbpBaseFilter
				{
				public:

					/// <summary>
					/// Constructs a new HttpAbpInclusionFilter object. Note that some preprocessing of
					/// the raw filter rule must have already been done to extract the options for the
					/// rule. This is handled by the HttpFilteringEngine object, so you should not try
					/// to contruct one of these objects directly, but rather use the provided interface
					/// in HttpFilteringEngine to load rules.
					/// 
					/// Notice that this is a subclass.. kind of without justification. The
					/// HttpAbpExceptionFilter has some justification because there are minor
					/// modifications to the matching process for the sake of exceptions to exceptions.
					/// However, inside HttpFilteringEngine for HttpAbpInclusionFilter objects, the
					/// functionality is straight forward. unordered_maps are used to map filters by
					/// domain key, so for inclusion filters, we simply push the included domains to the
					/// include map, and exception domains to the exceptions map with the exact same
					/// filter object.
					/// 
					/// The reason for this is that we treat an exception to an exception as an
					/// Inclusion filter, so if an Exception Filter gets a match, but the specified
					/// domain is an exception to the exception, we treat that as a positive match and
					/// block the request. I'm not sure if this was the intended purpose by the original
					/// filter syntax developers, but the logic follows.
					/// 
					/// Inclusion Filters are a little more black and white, they apply or they don't.
					/// Even though many of them have content-type exceptions, we're specifically
					/// talking in the context of domain exceptions.
					/// </summary>
					/// <param name="rule">
					/// The raw Adblock Plus formatted rule string to parse. 
					/// </param>
					/// <param name="settings">
					/// The settings specified for the rule. 
					/// </param>
					/// <param name="category">
					/// The category that the rule belongs to. Ads, Malware etc, represented as a 32 bit
					/// unsigned integer.
					/// </param>
					HttpAbpInclusionFilter(const std::string& rule, const HttpAbpFilterSettings settings, const uint8_t category);

					/// <summary>
					/// Default virtual destructor. 
					/// </summary>
					virtual ~HttpAbpInclusionFilter();
				};

			} /* namespace http */
		} /* namespace filtering */
	} /* namespace httpengine */
} /* namespace te */