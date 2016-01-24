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
#include <boost/utility/string_ref.hpp>
#include "../options/HttpFilteringOptions.hpp"
#include "HttpAbpFilterOptions.hpp"

namespace te
{
	namespace httpengine
	{
		namespace filtering
		{
			namespace http
			{				

				/// <summary>
				/// The HttpAbpBaseFilter object contains all of the base code for finalizing the
				/// parsing and matching of Adblock Plus Filters.
				/// </summary>
				class HttpAbpBaseFilter
				{

				public:

					/// <summary>
					/// Constructs a new HttpAbpBaseFilter object. Note that some preprocessing of the
					/// raw filter rule must have already been done to extract the options for the rule.
					/// This is handled by the HttpFilteringEngine object, so you should not try to
					/// contruct one of these objects directly, but rather use the provided interface in
					/// HttpFilteringEngine to load rules.
					/// </summary>
					/// <param name="rule">
					/// The raw Adblock Plus formatted rule string to parse. 
					/// </param>
					/// <param name="settings">
					/// The settings specified for the rule. 
					/// </param>
					/// <param name="category">
					/// The category that the rule belongs to. Ads, Malware etc.
					/// </param>
					HttpAbpBaseFilter(std::string rule, const HttpAbpFilterSettings settings, const uint8_t category);
				
					/// <summary>
					/// Default virtual destructor. 
					/// </summary>
					virtual ~HttpAbpBaseFilter();

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
					virtual bool IsMatch(boost::string_ref data, const HttpAbpFilterSettings dataSettings, boost::string_ref dataHost) const;

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
					HttpAbpFilterSettings GetFilterSettings() const;

					/// <summary>
					/// Convenience function for determining if, according to the settings for this
					/// filter, the filter's matching operation is bound to type information. This
					/// information is only ever available in an HTTP response, so by checking this
					/// property, the filtering engine can optimize away filter checks that are
					/// impossible to match at present. Obviously when the filter engine is checking
					/// a brand new request, it's not possible to have type information, so all
					/// typed selectors can simply be bypassed.
					/// </summary>
					/// <returns>
					/// True if this filter's matching operation is bound to a specific
					/// content-type, false otherwise.
					/// </returns>
					bool IsTypeBound() const;

				protected:

					/// <summary>
					/// Simple named keys for determing the type of a rule part.
					/// </summary>
					enum RulePartType
					{

						/// <summary>
						/// Anchored addresses bind the following rule to a specified domain. In the
						/// case of an anchored domain, all that must match is the HOST portion of
						/// the request.
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
						/// This is a very messy type of rule, because it's rather loosely defined
						/// and thus, complex. It's possible to define rules like
						/// |https://www.example.com/|, where the entire request string must match
						/// everything in between the two pipes exactly. However, it's also possible
						/// to use the opening pipe, but omit the closing pipe entirely. This
						/// complicates the rule, because in this case it's not possible to exactly
						/// match, since the closing pipe is omitted. We take such rules to be
						/// substring/partial matches of the request.
						/// </summary>
						RequestLiteralMatch = 4,

						/// <summary>
						/// As noted above, this rule allows to partially match the beginning of a
						/// request to a specific string. Such a rule is not terminated by a closing
						/// pipe, and as such, it's possible to add additional parameters to the
						/// request. In the event that the pipe is missing, EOF or another special
						/// character may denote the end of the substring/partial match. For
						/// example, "|https://*=*$domain=example.com" would match all requests
						/// to/from example.com which are requested over HTTPS, and also contain an
						/// equals sign in between any two portions of the request string.
						/// 
						/// For this rule time, we must first so an exact substring match against
						/// the request, ensuring the first 8 characters equal "https://".
						/// </summary>
						RequestLiteralPartialMatch = 5
					};

					/// <summary>
					/// This is a container of the different parts of a parsed rule. Rules are split up
					/// at special tokens such as "*|?". The m_rulePartsInt container and the
					/// m_ruleParts compliment eachother, in that the m_rulePartsInt container stores
					/// information about what kind of element m_ruleParts[n] is. Depending on the value
					/// of m_rulePartsInt[n], we can tell that m_ruleParts[n] is a string literal, an
					/// anchored domain, a wildcard character, separator, etc. We use this information
					/// in matching to quickly determine what the next step of matching is.
					/// 
					/// For example, if m_rulePartsInt[0] is a string literal, m_rulePartsInt[1] is a
					/// wildcard, and m_rulePartsInt[2] is another string literal, then the matching
					/// algorithm will do a simple find([0]) -&gt; then -&gt; find([2]) at least one
					/// char beyond the result of the first find.
					/// </summary>
					std::vector<boost::string_ref> m_ruleParts;

					/// <summary>
					/// See comments on m_ruleParts. 
					/// </summary>
					std::vector<RulePartType> m_rulePartTypes;

					/// <summary>
					/// Every single ABP filter can come with its own unique settings. These can get
					/// pretty complex. Aside from the $domain option, all of the other options serve as
					/// a binary indicator of what a filter can and can't apply to. This selector may
					/// apply to images, but not scripts, or third-party or not, etc. This stores the
					/// settings for a specific ABP Filter item.
					/// </summary>
					HttpAbpFilterSettings m_settings;

					/// <summary>
					/// A copy of the original rule string. This is kept for reference only, as the
					/// final form can differ a great deal after parsing and processing. This is kept as
					/// a reference so that one can easily debug the original input rule.
					/// </summary>
					std::string m_originalRuleString;

					/// <summary>
					/// The category that this filtering rule applies to. Consider the instance where
					/// one might subscribe to an ABP formatted list specifically for Ads, then another
					/// list for Malware, another for Pornography, etc. This is how we keep track of
					/// what category or list the rule originated from.
					/// </summary>
					uint8_t m_category = 0;

					/// <summary>
					/// A single-char pattern that can match to any character, one or more times. 
					/// </summary>
					static const boost::string_ref WildcardStrRef;

					/// <summary>
					/// A single-char pattern that can match / & ? etc.
					/// </summary>
					static const boost::string_ref SeparatorStrRef;

					/// <summary>
					/// All special characters of the ABP filtering syntax, including single anchors.
					/// </summary>
					static const boost::string_ref SpecialCharStrRef;

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
					bool SettingsApply(const HttpAbpFilterSettings transactionSettings, const HttpAbpFilterSettings ruleSettings) const;				

				};

			} /* namespace http */
		} /* namespace filtering */
	} /* namespace httpengine */
} /* namespace te */