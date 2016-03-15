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

#include <vector>
#include <string>
#include <tuple>
#include <unordered_set>
#include "../../../util/string/StringRefUtil.hpp"
#include <boost/utility/string_ref.hpp>
#include "../options/HttpFilteringOptions.hpp"
#include "AbpFilterOptions.hpp"
#include "../../util/cb/EventReporter.hpp"

namespace te
{
	namespace httpengine
	{
		namespace filtering
		{
			namespace http
			{				

				/// <summary>
				/// The AbpFilter object serves the purpose of denying or permitting an HTTP request
				/// or response from being completed based on host, URI and generated response
				/// payload content types.
				/// </summary>
				class AbpFilter : public util::cb::EventReporter
				{

					/// <summary>
					/// Allow the parser that constructs this object to be a friend. We all need
					/// friends.
					/// </summary>
					friend class AbpFilterParser;

				private:

					/// <summary>
					/// A single-char pattern that can match / & ? etc.
					/// </summary>
					static const boost::string_ref SeparatorStrRef;

					/// <summary>
					/// Simple named keys for determing the type of a rule part.
					/// </summary>
					enum RulePartType
					{

						/// <summary>
						/// An anchored domain string must be present exactly within the domain
						/// portion of the request in order to qualify as a match. The string must
						/// either match exactly from position 0 until LENGTH_OF_MATCH_STRING, or
						/// match at POSITION_OF_PERIOD_INDICATING_SUBDOMAIN until
						/// LENGTH_OF_MATCH_STRING. So, ||example.com can match http://example.com,
						/// http://www.example.com, http://sub.example.com, etc.
						/// </summary>
						AnchoredAddress = 0,

						/// <summary>
						/// Match anything.
						/// </summary>
						Wildcard = 1,

						/// <summary>
						/// Matches a valid URL seperator character, such as "/, ?, &" etc.
						/// </summary>
						Separator = 2,

						/// <summary>
						/// An exact string match.
						/// </summary>
						StringLiteral = 3,

						/// <summary>
						/// Any characters between an opening and (optional) ending pipe must
						/// exactly match the address of a request. If the end enclosing pipe is
						/// omitted, then then the text following the opening pipe up until EOF or
						/// another special character must exactly be present within the address of
						/// the request.
						/// </summary>
						AddressMatch = 4,

						/// <summary>
						/// End of address match applies whenever a single pipe is placed in a
						/// filter beyond position 0. Such a rule is interpreted in such a way that
						/// all text preceeding the ending pipe must exactly match a substring of
						/// the end of the request in equal length to LENGTH_OF_MATCH_STRING.
						/// </summary>
						EndOfAddressMatch = 5
					};					
				
				public:

					/// <summary>
					/// Constructs a new AbpFilter object. XXX TODO - This really should be private
					/// that only the parser can create instances, but I don't want the headache of
					/// a hack solution for make_shared to correctly function while this is private
					/// right now.
					/// </summary>
					AbpFilter(
						util::cb::MessageFunction onInfo = nullptr,
						util::cb::MessageFunction onWarning = nullptr,
						util::cb::MessageFunction onError = nullptr
						);

					/// <summary>
					/// Default virtual destructor. 
					/// </summary>
					virtual ~AbpFilter();

					/// <summary>
					/// Determine if the supplied data, given the options and the host, is found to
					/// match this filtering rule.
					/// </summary>
					/// <param name="data">
					/// A request URI to attempt matching against.
					/// </param>
					/// <param name="dataOptions">
					/// The options of request URI. When we receive the headers to a HTTP response,
					/// we can extract more details about the nature of the request and the content
					/// it will produce. For example, if the content-type header contains "/script"
					/// or "javascript", we know that the response content is a script. So, on the
					/// response we can create a HttpAbpFilterOption object and set opt[HttpAbpFilterOption::script].
					/// 
					/// This function will take those settings into consideration. For example if
					/// dataOptions[HttpAbpFilterOption::script] is set, and
					/// m_settings[HttpAbpFilterOption::notscript] is set, then we can immediately
					/// return false and avoid any uncessary computation.
					/// </param>
					/// <param name="dataHost">
					/// The host domain that the request was sent to. Although this is included in
					/// the data parameter, it is deliberately separated for certain types of
					/// filters so that they don't need to individually perform this task.
					/// </param>
					/// <returns>True if the filter was a match, false if not.</returns>
					virtual bool IsMatch(boost::string_ref data, const AbpFilterSettings dataSettings, boost::string_ref dataHost) const;

					/// <summary>
					/// The original formatting of ABP filters is lost during multiple stages of
					/// processing. This function is meant to provide a read-only to the retained,
					/// original filter string. This can be very useful for debugging filters.
					/// </summary>
					/// <returns>
					/// The original, unmodified filter string. 
					/// </returns>
					virtual const std::string& GetPattern() const;

					/// <summary>
					/// This function provides read-only access to the category that this filter belongs
					/// to. Ads, Malware etc.
					/// </summary>
					/// <returns>
					/// The category represented as a 32 bit unsigned integer. 
					/// </returns>
					uint8_t GetCategory() const;

					/// <summary>
					/// This function provides read-only access to the configured settings for a filter
					/// rule. The settings determine which types of request, based on metadata about
					/// that request, the filter can successfully match against.
					/// </summary>
					/// <returns>
					/// The configured filter settings. 
					/// </returns>
					AbpFilterSettings GetFilterSettings() const;

					/// <summary>
					/// Indicates if, according to the settings for this filter, the filter's
					/// matching operation is bound to type information. This information is only
					/// ever available in an HTTP response, so by checking this property, the
					/// filtering engine can optimize away filter checks that are impossible to
					/// match at present. Obviously when the filter engine is checking a brand new
					/// request, it's not possible to have response type information, so all typed
					/// selectors can simply be bypassed in this intial check.
					/// </summary>
					/// <returns>
					/// True if this filter's matching operation is bound to a specific
					/// content-type, false otherwise.
					/// </returns>
					bool IsTypeBound() const;

					/// <summary>
					/// Indicates whether or not a positive match from this AbpFilter object
					/// indicates that the transaction should be whitelisted or not.
					/// </summary>
					/// <returns>
					/// True if a positive match from this AbpFilter object should be interpreted as
					/// meaning that the transaction should be whitelisted, false otherwise.
					/// </returns>
					bool IsException() const;

					const std::unordered_set<boost::string_ref, util::string::StringRefHash>& GetExceptionDomains() const;

					const std::unordered_set<boost::string_ref, util::string::StringRefHash>& GetInclusionDomains() const;

				protected:					

					using FilterPart = std::tuple<boost::string_ref, RulePartType>;

					/// <summary>
					/// Components of the filtering rule.
					/// </summary>
					std::vector<FilterPart> m_filterParts;

					/// <summary>
					/// Container of all domains that are an exception to this rule.
					/// </summary>
					std::unordered_set<boost::string_ref, util::string::StringRefHash> m_exceptionDomains;

					/// <summary>
					/// Container of all domains that this rule applies to.
					/// </summary>
					std::unordered_set<boost::string_ref, util::string::StringRefHash> m_inclusionDomains;

					/// <summary>
					/// Every single ABP filter can come with its own unique settings. These can get
					/// pretty complex. Aside from the $domain option, all of the other options serve as
					/// a binary indicator of what a filter can and can't apply to. This selector may
					/// apply to images, but not scripts, or third-party or not, etc. This stores the
					/// settings for a specific ABP Filter item.
					/// </summary>
					AbpFilterSettings m_settings;

					/// <summary>
					/// A copy of the original rule string. This is kept for reference only, as the
					/// final form can differ a great deal after parsing and processing. This is kept as
					/// a reference so that one can easily debug the original input rule.
					/// </summary>
					std::string m_originalRuleString;

					/// <summary>
					/// The category that this filtering rule applies to. Consider the instance
					/// where one might subscribe to an ABP formatted list specifically for Ads,
					/// then another list for Malware, another for Pornography, etc. This is how we
					/// keep track of what category or list the rule originated from. This software
					/// is generally agnostic to the implied meaning of each category, except for a
					/// value of zero, which is a reserved category ID meant to indicate that no
					/// filtering should be done on a transaction.
					/// </summary>
					uint8_t m_category = 1;

					/// <summary>
					/// Indicates whether or not the constructed AbpFilter object has response type
					/// information as part of its criteria. This is important for optimization, as
					/// it is completely unnecessary to run type bound filters against initial
					/// requests, as they necessarily must be run only against requests that have
					/// already successfully generated at the very least response headers from a
					/// successful request.
					/// </summary>
					bool m_isTypeBound = false;

					/// <summary>
					/// Indicates whether or not the constructed AbpFilter object's matching
					/// mechnism is intended to indicate that the request/response in question is to
					/// be whitelisted upon a successful match or not.
					/// </summary>
					bool m_isException = false;

					/// <summary>
					/// Method for determining if two settings objects are compatible. In order to
					/// determine if a filtering rule applies to a certain transaction, the settings
					/// for the rule must match the extracted settings (traits) from the transaction
					/// in progress.
					/// 
					/// A match is necessary for a rule to be applied to the transaction.
					/// </summary>
					/// <param name="transactionSettings">
					/// The extracted settings (based on the traits) of the transaction. 
					/// </param>
					/// <param name="ruleSettings">
					/// The settings of the filtering rule in question. 
					/// </param>
					/// <returns>
					/// True of the rule filtering settings are compatible/applicable with the known
					/// transaction settings, false otherwise.
					/// </returns>
					bool SettingsApply(const AbpFilterSettings transactionSettings, const AbpFilterSettings ruleSettings) const;				

				};

			} /* namespace http */
		} /* namespace filtering */
	} /* namespace httpengine */
} /* namespace te */