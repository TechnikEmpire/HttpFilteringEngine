/*
* Copyright © 2017 Jesse Nicholson
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
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