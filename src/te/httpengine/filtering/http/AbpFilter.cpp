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

#include "AbpFilter.hpp"
#include <stdexcept>
#include "../../../util/string/StringRefUtil.hpp"
#include <cstring>

namespace te
{
	namespace httpengine
	{
		namespace filtering
		{
			namespace http
			{
				
				const boost::string_ref AbpFilter::SeparatorStrRef = u8"?&/=:";				

				AbpFilter::AbpFilter(
					util::cb::MessageFunction onInfo,
					util::cb::MessageFunction onWarning,
					util::cb::MessageFunction onError
					) : EventReporter(
						onInfo,
						onWarning,
						onError
						)
				{

				}

				AbpFilter::~AbpFilter()
				{
				}

				bool AbpFilter::IsMatch(boost::string_ref data, const AbpFilterSettings dataSettings, boost::string_ref dataHost) const
				{
					if (!SettingsApply(dataSettings, m_settings))
					{
						
						return false;
					}

					// If the host is in the exception domain list, just return false.
					if (m_exceptionDomains.find(dataHost) != m_exceptionDomains.end())
					{
						return false;
					}

					// If we have any inclusion domains at all, and if the current host is not found
					// within that list, then we return false.
					if (m_inclusionDomains.size() > 0)
					{
						if (m_inclusionDomains.find(dataHost) == m_inclusionDomains.end())
						{
							return false;
						}
					}

					auto dataCpy = data;

					size_t i = 0;

					auto len = m_filterParts.size();

					size_t lastMatch = 0;

					for (i = 0; i < m_filterParts.size(); ++i)
					{
						switch (std::get<1>(m_filterParts[i]))
						{
							// Anchored address matching is basically a confusing way to say that we
							// must match against the host of the request, AFAIK.
							case RulePartType::AnchoredAddress:
							{
								auto part = std::get<0>(m_filterParts[i]);
								auto hostLen = dataHost.size();
								auto plen = part.size();
								if (plen <= hostLen)
								{
									auto res = dataHost.find(part);

									if (res != boost::string_ref::npos)
									{
										if (res > 0 && (dataHost[res - 1] != '.' || dataHost[res - 1] != '/'))
										{											
											// Must either be the top level domain or a subdomain
											// match. So if not, this isn't a match.
											return false;
										}

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
									auto part = std::get<0>(m_filterParts[i]);
									data = data.substr(lastMatch);
									size_t literalTextPosition = data.find(part);

									if(literalTextPosition != boost::string_ref::npos)
									{
										lastMatch = literalTextPosition + part.size();
										continue;
									}
								}
								
								return false;
							}
							break;

							// Must be an exact match to the start of the request string.
							case RulePartType::AddressMatch:
							{
								auto part = std::get<0>(m_filterParts[i]);
								auto partSize = part.size();
								auto dataSize = dataCpy.size();

								if (partSize <= dataSize)
								{
									auto ss = dataCpy.substr(0, partSize);

									if (std::memcmp(ss.begin(), part.begin(), partSize) == 0)
									{
										lastMatch = partSize;
										continue;
									}
								}
								
								return false;
							}
							break;

							// Indicates that we must be at the end of the request string.
							case RulePartType::EndOfAddressMatch:
							{					
								if (lastMatch >= data.size() || data.size() == 0)
								{
									return true;
								}

								return false;
							}
							break;
						}
					}

					// All matches were found successfully so, we matched
					return true;
				}

				const std::string& AbpFilter::GetPattern() const
				{
					return m_originalRuleString;
				}

				uint8_t AbpFilter::GetCategory() const
				{
					return m_category;
				}

				AbpFilterSettings AbpFilter::GetFilterSettings() const
				{
					return m_settings;
				}

				bool AbpFilter::IsTypeBound() const
				{
					return m_isTypeBound;
				}

				bool AbpFilter::IsException() const
				{
					return m_isException;
				}

				const std::unordered_set<boost::string_ref, util::string::StringRefHash>& AbpFilter::GetExceptionDomains() const
				{
					return m_exceptionDomains;
				}

				const std::unordered_set<boost::string_ref, util::string::StringRefHash>& AbpFilter::GetInclusionDomains() const
				{
					return m_inclusionDomains;
				}

				bool AbpFilter::SettingsApply(const AbpFilterSettings transactionSettings, const AbpFilterSettings ruleSettings) const
				{					
					//auto f = transactionSettings.to_ulong();
					//auto l = ruleSettings.to_ulong();
					//
					//auto r = f & l;
					//
					//return r != 0;
					
					
					// Check to see if any opposite options are specified first. If the rule specifies explicitly that it does not apply
					// to third party requests, yet the transaction is specified to be a third-party request, then the rule doesn't apply.

					// If no opposing options are found to be set, then the only thing left to check is whether or not the content
					// types of the transaction and the rule are specified, in which case they must match exactly. Both of these
					// checks pass without conflict, then the rule is assumed to apply to the transaction in question.

					
					if (transactionSettings[AbpFilterOption::third_party] && ruleSettings[AbpFilterOption::notthird_party])
					{
						return false;
					}

					if (transactionSettings[AbpFilterOption::notthird_party] && ruleSettings[AbpFilterOption::third_party])
					{
						return false;
					}

					if (transactionSettings[AbpFilterOption::xmlhttprequest] && ruleSettings[AbpFilterOption::notxmlhttprequest])
					{
						return false;
					}

					if (transactionSettings[AbpFilterOption::notxmlhttprequest] && ruleSettings[AbpFilterOption::xmlhttprequest])
					{
						return false;
					}

					if (transactionSettings[AbpFilterOption::script] && ruleSettings[AbpFilterOption::notscript])
					{
						return false;
					}

					if (transactionSettings[AbpFilterOption::stylesheet] && ruleSettings[AbpFilterOption::notstylesheet])
					{
						return false;
					}

					if (transactionSettings[AbpFilterOption::image] && ruleSettings[AbpFilterOption::notimage])
					{
						return false;
					}

					if (ruleSettings[AbpFilterOption::stylesheet] ||
						ruleSettings[AbpFilterOption::script] ||
						ruleSettings[AbpFilterOption::image]
						)

					{
						bool noTypesMatch = true;

						if (noTypesMatch == true && (transactionSettings[AbpFilterOption::stylesheet] && ruleSettings[AbpFilterOption::stylesheet]))
						{
							noTypesMatch = false;
						}

						if (noTypesMatch == true && (transactionSettings[AbpFilterOption::script] && ruleSettings[AbpFilterOption::script]))
						{
							noTypesMatch = false;
						}

						if (noTypesMatch == true && (transactionSettings[AbpFilterOption::image] && ruleSettings[AbpFilterOption::image]))
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