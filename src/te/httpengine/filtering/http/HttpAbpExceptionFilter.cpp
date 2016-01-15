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

#include "HttpAbpExceptionFilter.hpp"

namespace te
{
	namespace httpengine
	{
		namespace filtering
		{
			namespace http
			{

				HttpAbpExceptionFilter::HttpAbpExceptionFilter(const std::string& rule, const HttpAbpFilterSettings settings, std::vector<std::string> exceptionDomains, const uint8_t category) :
					HttpAbpBaseFilter(rule, settings, category)
				{
					m_exceptionDomains = std::move(exceptionDomains);

					// Wrap all entries in boost::string_ref and push them to the unordered_set.
					for (auto& s = m_exceptionDomains.begin(); s != m_exceptionDomains.end(); ++s)
					{
						m_exceptionDomainsSet.insert(boost::string_ref(s->c_str()));
					}
				}

				HttpAbpExceptionFilter::~HttpAbpExceptionFilter()
				{

				}

				bool HttpAbpExceptionFilter::IsMatch(boost::string_ref data, const HttpAbpFilterSettings& dataSettings, boost::string_ref dataHost) const
				{
					// ABP filters can make your head hurt if you think about them for too long. One
					// of the things that can do this, is the fact that it's possible to define a
					// single expression which indicates an exception pattern (whitelist), while
					// also designating domains and other things that make an exception to the exception.
					// 
					// So what we're looking for, when checking to see if an exception rule applies,
					// is an exception to the exception, and if we find one, we can automatically
					// conclude that this exception filter does not apply. Exception inception.
					// We're not looking for these on the HttpAbpFilterOptions object, that's
					// checked in the HttpBaseFilter::IsMatch(...) method. Here, before we waste any
					// computation on that, we check to see if there's a domain exception, since
					// this is the most common and is immediately available information.
					// 
					// For more on the parsing and logic of these things, see
					// HttpAbpBaseFilter::IsMatch(...) and the parsing methods of the
					// HttpFilterEngine object.
					const auto& check = m_exceptionDomainsSet.find(dataHost);
					if (check != m_exceptionDomainsSet.end())
					{
						return false;
					}

					return HttpAbpBaseFilter::IsMatch(data, dataSettings, dataHost);
				}
			} /* namespace http */
		} /* namespace filtering */
	} /* namespace httpengine */
} /* namespace te */