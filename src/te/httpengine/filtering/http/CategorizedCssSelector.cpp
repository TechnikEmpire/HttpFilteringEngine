/*
* Copyright © 2017 Jesse Nicholson
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

#include "CategorizedCssSelector.hpp"
#include <Parser.hpp>

namespace te
{
	namespace httpengine
	{
		namespace filtering
		{
			namespace http
			{

				CategorizedCssSelector::CategorizedCssSelector(boost::string_ref domains, std::string selectorString, const uint8_t category)
					:m_domains(domains), m_category(category)
				{
					gq::Parser parser;

					// This can throw std::runtime_error!
					m_compiledSelector = parser.CreateSelector(selectorString, true);
				}

				CategorizedCssSelector::~CategorizedCssSelector()
				{

				}

				const boost::string_ref CategorizedCssSelector::GetOriginalSelectorString() const
				{
					if (m_compiledSelector != nullptr)
					{
						return m_compiledSelector->GetOriginalSelectorString();
					}

					return boost::string_ref();
				}

				const uint8_t CategorizedCssSelector::GetCategory() const
				{
					return m_category;
				}

				const gq::SharedSelector& CategorizedCssSelector::GetSelector() const
				{
					return m_compiledSelector;
				}

				const boost::string_ref CategorizedCssSelector::GetDomains() const
				{
					return m_domains;
				}

			} /* namespace http */
		} /* namespace filtering */
	} /* namespace httpengine */
} /* namespace te */