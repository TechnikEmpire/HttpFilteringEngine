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

#include "ProgramWideOptions.hpp"

namespace te
{
	namespace httpengine
	{
		namespace filtering
		{
			namespace options
			{

				ProgramWideOptions::ProgramWideOptions(const std::string& blockedPageHtml) : m_htmlBlockPagePayload(blockedPageHtml.begin(), blockedPageHtml.end())
				{
					// Must initialize all atomic bools to false explicitly.
					std::fill(m_httpContentFilteringCategories.begin(), m_httpContentFilteringCategories.end(), false);
					std::fill(m_httpFilteringOptions.begin(), m_httpFilteringOptions.end(), false);
				}

				ProgramWideOptions::~ProgramWideOptions()
				{

				}

				bool ProgramWideOptions::GetIsHttpCategoryFiltered(const uint8_t category) const
				{
					// Category 0 is reserved. Category zero is "unfiltered".
					// 
					// Also, 0 should always be false, that's what it's there to indicate, that
					// wherever you find this value, don't filter.
					if (category == 0 || category > m_httpContentFilteringCategories.size())
					{
						return false;
					}

					return m_httpContentFilteringCategories[category];
				}

				void ProgramWideOptions::SetIsHttpCategoryFiltered(const uint8_t category, const bool value)
				{
					// See remarks in ::GetIsHttpCategoryFiltered(...)
					if (category == 0 || category > m_httpContentFilteringCategories.size())
					{
						return;
					}

					m_httpContentFilteringCategories[category] = value;
				}

				bool ProgramWideOptions::GetIsHttpFilteringOptionEnabled(const http::HttpFilteringOption option) const
				{
					if (static_cast<uint32_t>(option) > m_httpFilteringOptions.size())
					{
						return false;
					}
					
					return m_httpFilteringOptions[static_cast<uint32_t>(option)];
				}

				void ProgramWideOptions::SetIsHttpFilteringOptionEnabled(const http::HttpFilteringOption option, const bool value)
				{
					if (static_cast<uint32_t>(option) > m_httpFilteringOptions.size())
					{
						return;
					}

					m_httpFilteringOptions[static_cast<uint32_t>(option)] = value;
				}

				std::vector<char> ProgramWideOptions::GetHtmlBlockedPagePayload() const
				{
					return m_htmlBlockPagePayload;
				}

			} /* namespace options */
		} /* namespace filtering */
	} /* namespace httpengine */
} /* namespace te */