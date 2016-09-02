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

#include <boost/utility/string_ref.hpp>
#include <Selector.hpp>
#include <Parser.hpp>
#include <memory>

namespace te
{
	namespace httpengine
	{
		namespace filtering
		{
			namespace http
			{

				/// <summary>
				/// The CategorizedCssSelector class serves as a lightweight wrapper around the
				/// Selector object from the third-party library GQ. In order to sort and store
				/// selectors based on the category that they belong to, such a wrapper is necessary.
				/// 
				/// The GQ Selector class represents a "compiled" CSS selector. This object is built
				/// by the GQ Parser object, which can throw naturally because it attempts to parse
				/// external user input. Since the CategorizedCssSelector accepts a raw selector
				/// string as input, construction of this object should be handled in an appropriate
				/// try/catch. GQ doesn't specify any custom exception classes, and as such simply
				/// throws all exceptions in std::runtime_error structures. The ::what() member
				/// contains detailed information for the exception, including precisely where the
				/// exception originated from.
				/// </summary>
				class CategorizedCssSelector
				{
					
				public:

					CategorizedCssSelector(boost::string_ref domains, std::string selectorString, const uint8_t category);
					~CategorizedCssSelector();

					/// <summary>
					/// The original formatting of ABP selectors is lost during multiple stages of
					/// processing. This function is meant to provide a read-only to the retained,
					/// original filter string. This can be very useful for debugging filters.
					/// </summary>
					/// <returns>
					/// The original, unmodified filter string. 
					/// </returns>
					const boost::string_ref GetOriginalSelectorString() const;

					/// <summary>
					/// This function provides read-only access to the category that this selector belongs
					/// to. Ads, Malware etc.
					/// </summary>
					/// <returns>
					/// The category represented as a 32 bit unsigned integer. 
					/// </returns>
					const uint8_t GetCategory() const;

					/// <summary>
					/// Gets the underlying compiled shared GQ Selector object.
					/// </summary>
					/// <returns>
					/// The underlying compiled shared GQ Selector.
					/// </returns>
					const gq::SharedSelector& GetSelector() const;

					/// <summary>
					/// If the selector is a donain specific selector, retrieves the domains for the
					/// specified selector.
					/// </summary>
					/// <returns>
					/// If the selector is domain specific, a comma separated list of the domains
					/// that selector applies to. If not domain specific, an empty string_ref.
					/// </returns>
					const boost::string_ref GetDomains() const;

				private:

					/// <summary>
					/// The category that this selector applies to. Consider the instance where one
					/// might subscribe to an ABP formatted list specifically for Ads, then another
					/// list for Malware, another for Pornography, etc. This is how we keep track of
					/// what category or list the rule originated from, so the user can
					/// enable/disable them at will.
					/// </summary>
					uint8_t m_category = 0;

					/// <summary>
					/// If the selector string supplied during object construction is considered to
					/// be complex, then a selector engine object will be built. Complex selectors
					/// must run through a selector engine to be handled correctly.
					/// 
					/// If the selector is trivial, this member will remain nullptr.
					/// </summary>
					gq::SharedSelector m_compiledSelector = nullptr;

					/// <summary>
					/// If this is a domain specific selector, then this string contains one or more
					/// domains that the selector belongs to.
					/// </summary>
					boost::string_ref m_domains;

				};

			} /* namespace http */
		} /* namespace filtering */
	} /* namespace httpengine */
} /* namespace te */