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

#include "HttpAbpBaseFilter.hpp"
#include <stdexcept>
#include "../../../util/string/StringRefUtil.hpp"

namespace te
{
	namespace httpengine
	{
		namespace filtering
		{
			namespace http
			{
				const boost::string_ref HttpAbpBaseFilter::WildcardStrRef = u8"*";
				const boost::string_ref HttpAbpBaseFilter::SeparatorStrRef = u8"^?&/=:";
				const boost::string_ref HttpAbpBaseFilter::SpecialCharStrRef = u8"*|^?&/=:";

				HttpAbpBaseFilter::HttpAbpBaseFilter(
					std::string rule,
					const HttpAbpFilterSettings settings,
					const uint8_t category
					) :
					m_settings(settings), m_category(category)
				{
					// We do the final stages of parsing inside the object here. As already
					// mentioned, some processing of the rule has already been done by the
					// HttpFilterEngine object before getting to this point. Here, the job to be
					// done is to scan through the expression looking for special characters that
					// are left, which at this point basically only includes |, ||, ^ and *. From
					// these characters, we split the rule into chunks and decide if they are string
					// literals (like searching for exactly "foobar/chimps" in a path), a wildcard,
					// which just means 1 or more chars between the previous and next filter parts,
					// domain anchors which can be used to specify specific address information, and
					// of course separating characters.
					//
					// We keep static const references of all of these things to keep it clean,
					// avoid creating/copying/destroying temporaries, etc. We also use
					// boost::string_ref, because they're cheap and very fast with basic string ops
					// and don't copy or control the underlying data at all.
					//
					// XXX TODO - The parsing in this code is not very robust, and more error checking
					// code should be added. In fact, a full blown external parser should probably be
					// done.

					m_originalRuleString = rule;
					m_settings = settings;
					m_category = category;

					boost::string_ref originalRuleStrRef(m_originalRuleString);

					// Reservations to avoid exponential allocations
					boost::string_ref cref = originalRuleStrRef;
					if (cref.length() > 2 && cref[0] == '|' && cref[1] == '|') { cref = cref.substr(2); }
					uint8_t splits = 1;
					auto cind = cref.find_first_of(SpecialCharStrRef);
					while (cind != boost::string_ref::npos)
					{
						splits++;
						cref = cref.substr(cind + 1);
						cind = cref.find_first_of(SpecialCharStrRef);
					}
					m_ruleParts.reserve(splits);
					m_rulePartTypes.reserve(splits);
					//

					if (originalRuleStrRef.length() > 2 && originalRuleStrRef[0] == '|' && originalRuleStrRef[1] == '|')
					{
						// This means that the rule expression begins with a domain anchor, ||. We
						// remove these chars, extract the specified address/domain information.
						// Double anchors like this indiciates that this filter will apply to
						// ads.example.com, somecrap.example.com, www.example.com, on both
						// http/https, but this filter will not apply to stupidexample.com. ||
						// basically just means that following address must either be be proceeded
						// by a '.' or a 'http://' or 'https://', for simplicitly.
						//
						// https://adblockplus.org/en/filters#anchors

						// Remove the anchors "||"
						originalRuleStrRef = originalRuleStrRef.substr(2);

						auto nextSpecialChar = originalRuleStrRef.find_first_of(SpecialCharStrRef);

						if (nextSpecialChar == boost::string_ref::npos)
						{
							// Rule is JUST an anchored domain. In this case, we'll just stop and return.

							m_ruleParts.push_back(originalRuleStrRef);

							m_rulePartTypes.push_back(RulePartType::AnchoredAddress);

							return;
						}
						else
						{
							// Rule is an anchored domain PLUS additional special characters. More parsing
							// must be done after the anchored domain is extracted.
							boost::string_ref address = originalRuleStrRef.substr(0, nextSpecialChar);

							m_ruleParts.push_back(address);

							m_rulePartTypes.push_back(RulePartType::AnchoredAddress);

							switch (originalRuleStrRef[nextSpecialChar])
							{
								case '*':
								{
									m_ruleParts.push_back(WildcardStrRef);
									m_rulePartTypes.push_back(RulePartType::Wildcard);
								}
								break;

								case '|':
								{
									// Not properly formatted.
									throw new std::runtime_error("In HttpAbpBaseFilter::HttpAbpBaseFilter(std::string, const HttpAbpFilterSettings, const uint8_t) - Anchored domain followed by request matching pipe '|' character.");
								}
								break;

								default:
								{
									// Must be a separator.
									m_ruleParts.push_back(SeparatorStrRef);
									m_rulePartTypes.push_back(RulePartType::Separator);
								}
								break;
							}

							originalRuleStrRef = originalRuleStrRef.substr(nextSpecialChar + 1);
						}
					}
					else if (originalRuleStrRef.length() > 1 && originalRuleStrRef[0] == '|')
					{
						// When a rule begins with a single pipe, this rule is a little messy and
						// not very well defined. On paper, there is supposed to be a second pipe
						// somewhere in the rule string. Everything within these two pipes must be
						// matched against the entire request. By "entire request", this means the
						// full URL with the METHOD and possibly SERVICE attached. METHOD of course
						// being http:// or https://, and SERVICE (optional) being "www.". Whatever
						// the full URL is of the request or response being checked, this rule must
						// precisely match.
						//
						// However, in practice, this isn't the case. Almost every single rule using
						// this feature in the EasyList does not have a closing pipe. I can only
						// assume then that the unwritten rule is that if there is no closing pipe,
						// then EOF or the next special character substitutes for the closing pipe
						// in such a rule.
						//
						// HOWEVER STILL, as previously mentioned, the URL is supposed to exactly
						// match, yet a great many of the rules contain special characters, then
						// follow with string literals, then more special characters. So how can
						// we exactly match "|http://*=*" ?? We can't comply with this by the language
						// given for the syntax officially.
						//
						// Instead, we need to treat these rules as follows:
						//	A) Rule starts with a pipe. This means that the full request string must
						//	   exactly match the following string literal starting at position 0 in the
						//     request string.
						//
						//	B) If a closing pipe is found, then the entire request string must match
						//	   exactly the string literal contained between two pipes, and no further
						//     characters can be included as part of the filter matching string.
						//
						//	C) If no closing pipe is found, then either EOF or the next special character
						//	   in the filter string denotes the end of the string literal. The string literal
						//	   extracted that immediately follows the opening pipe and is terminated by either
						//	   EOF or a special character must exactly match the full request URL ONLY for
						//	   the first N characters which are of equal length to the extracted string literal.
						//
						//	D) In the event that no closing pipe was found and it was a special character that
						//	   marked the end of the literal request match string, then the regular matching
						//	   process applies to the rest of the filtering string.
						//
						//	DEFINITIONS:
						//		"string literal" - I've totally abused the meaning of a string in source code
						//		and applied to mean, in the context of ABP filters, a sequence of 1 or more
						//		characters which is not a recognized special character.
						//
						//	REFERENCES:
						//		https://adblockplus.org/filter-cheatsheet#blocking3

						// Erase the first domain anchor
						originalRuleStrRef = originalRuleStrRef.substr(1);

						auto closingPos = originalRuleStrRef.find_first_of(SpecialCharStrRef);

						// If not found, we have a broken rule so just ignore
						if (closingPos != boost::string_ref::npos)
						{
							boost::string_ref address = originalRuleStrRef.substr(0, closingPos);

							switch (originalRuleStrRef[closingPos])
							{
								case '*':
								{
									// Since we didn't break with a closing pipe, we push the
									// address as a partial match, then we worry about the special character.
									m_ruleParts.push_back(address);
									m_rulePartTypes.push_back(RulePartType::RequestLiteralMatch);

									m_ruleParts.push_back(WildcardStrRef);
									m_rulePartTypes.push_back(RulePartType::Wildcard);
								}
								break;

								case '|':
								{
									// Since we got a closing pipe, we require a literal match. The
									// rest of the rule can/must be simply ignored. Remember, the
									// rules are already split off and processed externally.
									m_ruleParts.push_back(address);
									m_rulePartTypes.push_back(RulePartType::RequestLiteralMatch);
									return;
								}
								break;

								default:
								{
									// Since we didn't break with a closing pipe, we push the
									// address as a partial match, then we worry about the special character.
									m_ruleParts.push_back(address);
									m_rulePartTypes.push_back(RulePartType::RequestLiteralMatch);

									// Must be a separator.
									m_ruleParts.push_back(SeparatorStrRef);
									m_rulePartTypes.push_back(RulePartType::Separator);
								}
								break;
							}

							originalRuleStrRef = originalRuleStrRef.substr(closingPos + 1);
						}
						else
						{
							// If no closing anchor or special character was found, then we simply take
							// what we have. Must have been an EOF termination, so we're done, hence
							// we return.
							m_ruleParts.push_back(originalRuleStrRef);
							m_rulePartTypes.push_back(RulePartType::RequestLiteralPartialMatch);
							return;
						}
					}

					if (originalRuleStrRef.size() == 0)
					{
						// In case the anchored/literal code consumed everything.
						return;
					}

					// Whether this is an anchored rule, literal match, etc, at this point it
					// doesn't matter. Any of that, if it existed at all, will have already been
					// handled, so we simply worry about processing the rule looking for special
					// characters such as separators and string literals for matching.
					auto nextSpecialChar = originalRuleStrRef.find_first_of(SpecialCharStrRef);

					if (nextSpecialChar == boost::string_ref::npos)
					{
						// Rule is just a string literal
						m_ruleParts.push_back(originalRuleStrRef);

						m_rulePartTypes.push_back(RulePartType::StringLiteral);
					}
					else
					{			
						
						while (originalRuleStrRef.size() > 0 && nextSpecialChar != boost::string_ref::npos)
						{							
							if (nextSpecialChar > 0)
							{
								boost::string_ref part = originalRuleStrRef.substr(0, nextSpecialChar);

								m_ruleParts.push_back(part);

								m_rulePartTypes.push_back(RulePartType::StringLiteral);

								originalRuleStrRef = originalRuleStrRef.substr(nextSpecialChar);
							}

							switch (originalRuleStrRef[nextSpecialChar])
							{
								case '*':
								{
									m_ruleParts.push_back(WildcardStrRef);
									m_rulePartTypes.push_back(RulePartType::Wildcard);
								}
								break;

								case '|':
								{
									// Not properly formatted.
									throw new std::runtime_error("In HttpAbpBaseFilter::HttpAbpBaseFilter(std::string, const HttpAbpFilterSettings, const uint8_t) - Anchored domain followed by request matching pipe '|' character.");
								}
								break;

								default:
								{
									// Must be a separator.
									m_ruleParts.push_back(SeparatorStrRef);
									m_rulePartTypes.push_back(RulePartType::Separator);
								}
								break;
							}

							originalRuleStrRef = originalRuleStrRef.substr(1);

							nextSpecialChar = originalRuleStrRef.find_first_of(SpecialCharStrRef);
						}

						// If there is any part of the string that we have not consumed, and we
						// failed to find another special character, then whatever is left over is a
						// string literal that must be matched.
						if (originalRuleStrRef.size() > 0)
						{							
							m_ruleParts.push_back(originalRuleStrRef);

							m_rulePartTypes.push_back(RulePartType::StringLiteral);
						}
					}
				}

				HttpAbpBaseFilter::~HttpAbpBaseFilter()
				{
				}

				bool HttpAbpBaseFilter::IsMatch(boost::string_ref data, const HttpAbpFilterSettings dataSettings, boost::string_ref dataHost) const
				{
					if (!SettingsApply(dataSettings, m_settings))
					{
						return false;
					}

					size_t i = 0;

					auto len = m_ruleParts.size();

					size_t lastMatch = 0;

					for (i = 0; i < m_ruleParts.size(); ++i)
					{
						switch (m_rulePartTypes[i])
						{
							// Anchored address matching is basically a confusing way to say that we
							// must match against the host of the request, AFAIK.
							// 
							// However, we have a double wammy. If we match against the host, we
							// need to then find that same matched string in the full request and
							// substring the data from beyond our matched address string. This is a
							// PITA and a bit of a waste, but we check the dataHost member first
							// specifically, to avoid false positives, such as Google search results
							// that embed a URL we're trying to match against in GET parameters.
							case RulePartType::AnchoredAddress:
							{
								auto hostLen = dataHost.size();
								auto plen = m_ruleParts[i].size();
								if (plen <= hostLen)
								{
									auto res = dataHost.find(m_ruleParts[i]);

									if (res != boost::string_ref::npos)
									{
										auto hostInReqPos = data.find(dataHost);

										if (hostInReqPos != boost::string_ref::npos)
										{
											lastMatch = hostInReqPos + res + plen;
											continue;
										}
									}
								}

								return false;
							}
							break;

							case RulePartType::Wildcard:
							{
								// Wildcard, so as long as we have one additional character, we can move on.
								if (lastMatch + 1 <= data.size())
								{
									++lastMatch;
									continue;
								}

								return false;
							}
							break;

							case RulePartType::Separator:
							{
								if (lastMatch < data.size())
								{
									data = data.substr(lastMatch);

									auto sepPosition = data.find_first_of(SeparatorStrRef);

									if (sepPosition != boost::string_ref::npos)
									{
										lastMatch = sepPosition + 1;
										continue;
									}
								}	
								
								return false;
							}
							break;

							case RulePartType::StringLiteral:
							{
								if (lastMatch < data.size())
								{
									data = data.substr(lastMatch);
									size_t literalTextPosition = data.find(m_ruleParts[i]);

									if(literalTextPosition != boost::string_ref::npos)
									{
										lastMatch = literalTextPosition + m_ruleParts[i].size();
										continue;
									}
								}
								
								return false;
							}
							break;

							// Must be an exact match.
							case RulePartType::RequestLiteralMatch:
							{
								return util::string::Equal(data, m_ruleParts[i]);
							}
							break;

							// Basically just a substring match against the start of the request.
							case RulePartType::RequestLiteralPartialMatch:
							{								
								auto plen = m_ruleParts[i].size();
								auto reqSize = data.size();
								if (plen <= reqSize)
								{
									auto sub = data.substr(0, plen);

									if (util::string::Equal(m_ruleParts[i], sub))
									{
										lastMatch = plen;
										continue;
									}
								}

								return false;
							}
							break;
						}
					}

					// All matches were found successfully so, we matched
					return true;
				}

				const std::string& HttpAbpBaseFilter::GetPattern() const
				{
					return m_originalRuleString;
				}

				uint8_t HttpAbpBaseFilter::GetCategory() const
				{
					return m_category;
				}

				HttpAbpFilterSettings HttpAbpBaseFilter::GetFilterSettings() const
				{
					return m_settings;
				}

				bool HttpAbpBaseFilter::IsTypeBound() const
				{
					// If the filter specifies explicitly that it does or does NOT apply to a
					// specific content-type, then the filter is content-type bound and can only
					// possibly accurately match when HTTP responses are available.
					if (m_settings[HttpAbpFilterOption::script] || 
						m_settings[HttpAbpFilterOption::notscript] ||
						m_settings[HttpAbpFilterOption::stylesheet] ||
						m_settings[HttpAbpFilterOption::notstylesheet] || 
						m_settings[HttpAbpFilterOption::image] ||
						m_settings[HttpAbpFilterOption::notimage]
						)
					{
						return true;
					}

					return false;
				}

				bool HttpAbpBaseFilter::SettingsApply(const HttpAbpFilterSettings transactionSettings, const HttpAbpFilterSettings ruleSettings) const
				{
					// Check to see if any opposite options are specified first. If the rule specifies explicitly that it does not apply
					// to third party requests, yet the transaction is specified to be a third-party request, then the rule doesn't apply.

					// If no opposing options are found to be set, then the only thing left to check is whether or not the content
					// types of the transaction and the rule are specified, in which case they must match exactly. Both of these
					// checks pass without conflict, then the rule is assumed to apply to the transaction in question.

					if (transactionSettings[HttpAbpFilterOption::third_party] && ruleSettings[HttpAbpFilterOption::notthird_party])
					{
						return false;
					}

					if (transactionSettings[HttpAbpFilterOption::notthird_party] && ruleSettings[HttpAbpFilterOption::third_party])
					{
						return false;
					}

					if (transactionSettings[HttpAbpFilterOption::xmlhttprequest] && ruleSettings[HttpAbpFilterOption::notxmlhttprequest])
					{
						return false;
					}

					if (transactionSettings[HttpAbpFilterOption::notxmlhttprequest] && ruleSettings[HttpAbpFilterOption::xmlhttprequest])
					{
						return false;
					}

					if (transactionSettings[HttpAbpFilterOption::script] && ruleSettings[HttpAbpFilterOption::notscript])
					{
						return false;
					}

					if (transactionSettings[HttpAbpFilterOption::stylesheet] && ruleSettings[HttpAbpFilterOption::notstylesheet])
					{
						return false;
					}

					if (transactionSettings[HttpAbpFilterOption::image] && ruleSettings[HttpAbpFilterOption::notimage])
					{
						return false;
					}

					if (ruleSettings[HttpAbpFilterOption::stylesheet] ||
						ruleSettings[HttpAbpFilterOption::script] ||
						ruleSettings[HttpAbpFilterOption::image]
						)

					{
						bool noTypesMatch = true;

						if (noTypesMatch == true && (transactionSettings[HttpAbpFilterOption::stylesheet] && ruleSettings[HttpAbpFilterOption::stylesheet]))
						{
							noTypesMatch = false;
						}

						if (noTypesMatch == true && (transactionSettings[HttpAbpFilterOption::script] && ruleSettings[HttpAbpFilterOption::script]))
						{
							noTypesMatch = false;
						}

						if (noTypesMatch == true && (transactionSettings[HttpAbpFilterOption::image] && ruleSettings[HttpAbpFilterOption::image]))
						{
							noTypesMatch = false;
						}

						if (noTypesMatch)
						{
							return false;
						}
					}

					return true;
				}

			} /* namespace http */
		} /* namespace filtering */
	} /* namespace httpengine */
} /* namespace te */