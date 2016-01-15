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

#include <unordered_set>
#include "HttpAbpBaseFilter.hpp"
#include "../../../util/string/StringRefUtil.hpp"

namespace te
{
	namespace httpengine
	{
		namespace filtering
		{
			namespace http
			{

				/// <summary>
				/// The HttpAbpExceptionFilter object is a specialized subclass of HttpAbpBaseFilter
				/// designed to handle Adblock Plus Exception Filters, specifically addressing some
				/// of the quirks that come along with exceptions, such as exceptions to exceptions.
				/// </summary>
				class HttpAbpExceptionFilter : public HttpAbpBaseFilter
				{
				
				public:

					/// <summary>
					/// Constructs a new HttpAbpExceptionFilter object. Note that some preprocessing of
					/// the raw filter rule must have already been done to extract the options for the
					/// rule. This is handled by the HttpFilteringEngine object, so you should not try
					/// to contruct one of these objects directly, but rather use the provided interface
					/// in HttpFilteringEngine to load rules.
					/// </summary>
					/// <param name="rule">
					/// The raw Adblock Plus formatted rule string to parse. 
					/// </param>
					/// <param name="settings">
					/// The settings specified for the rule. 
					/// </param>
					/// <param name="domains">
					/// A copy of the value of the "$domains=" portion of the rule, if specified. 
					/// </param>
					/// <param name="category">
					/// The category that the rule belongs to. Ads, Malware etc, represented as a 32 bit
					/// unsigned integer.
					/// </param>
					HttpAbpExceptionFilter(const std::string& rule, const HttpAbpFilterSettings settings, std::vector<std::string> exceptionDomains, const uint8_t category);
				
					/// <summary>
					/// Default virtual destructor. 
					/// </summary>
					virtual ~HttpAbpExceptionFilter();

					/// <summary>
					/// Determine if the supplied data, given the options and the host, is found to
					/// match this filtering rule. This overridden function simply checks to see if the
					/// dataHost specified is listed as an exception to the exception filter and if not,
					/// delegates the matching to HttpAbpBaseFilter::IsMatch(...).
					/// </summary>
					/// <param name="data">
					/// A request URI to attempt matching against. 
					/// </param>
					/// <param name="dataOptions">
					/// The options of request URI. When we receive the headers to a HTTP response, we
					/// can extract more details about the nature of the request and the content it will
					/// produce. For example, if the content-type header contains "/script" or
					/// "javascript", we know that the response content is a script. So, on the response
					/// we can create a HttpAbpFilterOption object and set
					/// opt[HttpAbpFilterOption::script].
					/// 
					/// HttpAbpBaseFilter::IsMatch(...) will take those settings into consideration. For
					/// example if dataOptions[HttpAbpFilterOption::script] is set, and
					/// m_settings[HttpAbpFilterOption::notscript] is set, then we can immediately
					/// return false and avoid any uncessary computation.
					/// </param>
					/// <param name="dataHost">
					/// The host domain that the request was sent to. 
					/// </param>
					/// <returns>
					/// True if the filter was a match, false if not. 
					/// </returns>
					virtual bool IsMatch(boost::string_ref data, const HttpAbpFilterSettings& dataSettings, boost::string_ref dataHost) const;

				private:
					/// <summary>
					/// In order to address the problem of exceptions to exceptions, m_domainsStr
					/// holds a copy of the $domains=... option that may or may not have been
					/// specified as part of this exception filter. It is very common in exception
					/// filters to hold exceptions to exceptions, or to specify a single applicable
					/// domain. By retaining this data, we can quickly eliminate or qualify requests
					/// from being checked against the rest of the filter.
					/// 
					/// This container holds the raw std::string objects of each exception domain in
					/// memory, while the m_exceptionDomainsSet wraps each entry in this collection
					/// with string_ref objects. This container preserves the actual strings simply
					/// to allow the corresponding unordered_set to function.
					/// </summary>
					std::vector<std::string> m_exceptionDomains;

					/// <summary>
					/// Since filter objects are given data in string_ref structures, we keep our
					/// exception domains wrapped in string_ref objects and push them to this map.
					/// </summary>
					std::unordered_set<boost::string_ref, util::string::StringRefHash> m_exceptionDomainsSet;

				};

			} /* namespace http */
		} /* namespace filtering */
	} /* namespace httpengine */
} /* namespace te */