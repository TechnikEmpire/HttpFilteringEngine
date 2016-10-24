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

#include "AbpFilterParser.hpp"

namespace te
{
	namespace httpengine
	{
		namespace filtering
		{
			namespace http
			{

				const std::unordered_map<boost::string_ref, AbpFilterOption,  util::string::StringRefHash> AbpFilterParser::ValidFilterOptions
				{
					{ u8"script" , script },
					{ u8"~script" , notscript },
					{ u8"image" , image },
					{ u8"~image" , notimage },
					{ u8"stylesheet" , stylesheet },
					{ u8"~stylesheet" , notstylesheet },
					{ u8"object" , object },
					{ u8"~object" , notobject },
					{ u8"object-subrequest" , object_subrequest },
					{ u8"~object-subrequest" , notobject_subrequest },
					{ u8"subdocument" , subdocument },
					{ u8"~subdocument" , notsubdocument },
					{ u8"document" , document },
					{ u8"~document" , notdocument },
					{ u8"elemhide" , elemhide },
					{ u8"~elemhide" , notelemhide },
					{ u8"third-party" , third_party },
					{ u8"~third-party" , notthird_party },
					{ u8"xmlhttprequest" , xmlhttprequest },
					{ u8"~xmlhttprequest" , notxmlhttprequest }
				};

				AbpFilterParser::AbpFilterParser(
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

				AbpFilterParser::~AbpFilterParser()
				{

				}

				AbpFilterParser::SharedFilter AbpFilterParser::Parse(const std::string& filterString, const uint8_t category) const
				{

					if (filterString.size() == 0)
					{
						throw std::runtime_error(u8"In AbpFilterParser::Parse(const std::string&, const uint8_t) - Expected filter string, got empty string.");
					}

					if (category == 0)
					{
						throw std::runtime_error(u8"In AbpFilterParser::Parse(const std::string&, const uint8_t) - Category unsigned eight bit integer argument has value of zero. Zero is a category reserved to indicate no filtering.");
					}

					// It is necessary to copy construct the internal
					// AbpFilter::m_originalRuleString member from the supplied raw filter string
					// before doing our processing. This is necessary because we're generating rule
					// parts out of string_ref objects, which will internally refer back to the
					// wrapped string. The string must be preserved for the lifetime of these string
					// references, so we do this first, then create our initial string_ref.

					SharedFilter filter = std::make_shared<AbpFilter>(m_onInfo, m_onWarning, m_onError);	

					if (filter == nullptr)
					{
						throw std::runtime_error(u8"In AbpFilterParser::Parse(const std::string&, const uint8_t) - Failed to allocate new shared AbpFilter object.");
					}

					filter->m_originalRuleString = filterString;

					boost::string_ref filterStringRef(filter->m_originalRuleString);

					boost::string_ref filterStringOptionsRef;

					// First lets split the options and the settings into two different string_refs.
					auto lastOptionCharPos = filterStringRef.find_last_of('$');

					if (lastOptionCharPos != boost::string_ref::npos)
					{
						filterStringOptionsRef = filterStringRef.substr(lastOptionCharPos);
						filterStringRef = filterStringRef.substr(0, lastOptionCharPos);
					}

					bool isException = false;

					if (filterStringRef.size() > 2 && filterStringRef[0] == '@' && filterStringRef[1] == '@')
					{
						isException = true;
						filterStringRef = filterStringRef.substr(2);
					}

					filter->m_isException = isException;

					auto inclusionDomains = ParseDomains(filterStringOptionsRef, false);
					auto exceptionDomains = ParseDomains(filterStringOptionsRef, true);
					auto filterSettings = ParseSettings(filterStringOptionsRef);

					std::vector<FilterPart> parts;

					bool hasDoubleAnchor = false;
					bool hasOpeningAnchor = false;
					bool hasClosingAnchor = false;

					while (filterStringRef.size() > 0)
					{
						auto p = ParseFilterPart(filterStringRef);
						auto pt = std::get<1>(p);

						if (hasClosingAnchor)
						{
							// Nothing should be allowed after a closing anchor.
							throw std::runtime_error(u8"In AbpFilterParser::Parse(const std::string&, const uint8_t) - Cannot have more tokens beyond the end of address anchor operator.");
						}

						switch (pt)
						{
							case AbpFilter::RulePartType::AnchoredAddress:
							{
								if (hasDoubleAnchor)
								{
									throw std::runtime_error(u8"In AbpFilterParser::Parse(const std::string&, const uint8_t) - More than one domain anchor in filtering rule.");
								}
								else if(hasOpeningAnchor)
								{
									throw std::runtime_error(u8"In AbpFilterParser::Parse(const std::string&, const uint8_t) - Opening anchor for address match and domain anchor in filtering rule.");
								}
								else
								{
									hasDoubleAnchor = true;
								}
							}
							break;

							case AbpFilter::RulePartType::AddressMatch:
							{
								if (hasDoubleAnchor)
								{
									throw std::runtime_error(u8"In AbpFilterParser::Parse(const std::string&, const uint8_t) - Opening anchor for address match and domain anchor in filtering rule.");
								}
								else
								{
									hasOpeningAnchor = true;
								}
							}
							break;

							case AbpFilter::RulePartType::EndOfAddressMatch:
							{
								hasClosingAnchor = true;
							}
							break;
						}
						
						parts.emplace_back(p);
					}

					if (parts.size() == 0)
					{
						throw std::runtime_error(u8"In AbpFilterParser::Parse(const std::string&, const uint8_t) - Failed to parse any filtering rule parts.");
					}

					bool isTypeBound = false;

					if (filterSettings[AbpFilterOption::script] ||
						filterSettings[AbpFilterOption::notscript] ||
						filterSettings[AbpFilterOption::stylesheet] ||
						filterSettings[AbpFilterOption::notstylesheet] ||
						filterSettings[AbpFilterOption::image] ||
						filterSettings[AbpFilterOption::notimage]
						)
					{
						isTypeBound = true;
					}

					filter->m_isTypeBound = isTypeBound;

					filter->m_settings = filterSettings;

					//filter->m_filterParts = std::move(parts);

					//filter->m_inclusionDomains = std::move(inclusionDomains);
					
					//filter->m_exceptionDomains = std::move(exceptionDomains);

					filter->m_category = category;

					if (lastOptionCharPos != boost::string_ref::npos)
					{
						// Now that we've parsed the options, don't keep them around 
						// in memory as a string.
						filter->m_originalRuleString = filter->m_originalRuleString.substr(0, lastOptionCharPos);
					}

					return filter;
				}

				AbpFilterParser::FilterPart AbpFilterParser::ParseFilterPart(boost::string_ref& filterStr, const boost::string_ref::size_type pos) const
				{
					auto cpos = pos;
					auto max = filterStr.size();
					bool notDone = true;

					boost::string_ref::size_type collected = 0;

					auto GetCollected = [&filterStr](const size_t count, const size_t startPosition, const size_t endPosition) 
					{
						if (count > 0)
						{
							auto ss = filterStr.substr(startPosition, count);
							filterStr = filterStr.substr(endPosition);
							return ss;
						}

						return boost::string_ref();
					};

					for (cpos; cpos < max; ++cpos)
					{
						switch (filterStr[cpos])
						{
							// Separator
							case '^':
							{
								// If we've collected non-special characters before this, then we need to return that
								// and leave off at this special char. When this function is called again, the special
								// char and its correct type will be returned.
								auto curCollected = GetCollected(collected, pos, cpos);
								collected = 0;

								if (curCollected.size() > 0)
								{									
									return std::make_tuple(curCollected, AbpFilter::RulePartType::StringLiteral);
								}

								++cpos;
								filterStr = filterStr.substr(cpos);
								return std::make_tuple(boost::string_ref(u8"^"), AbpFilter::RulePartType::Separator);
							}
							break;

							case '|':
							{

								// So for anchors, we need to have one of three scenarios happen for
								// this to be valid and parsed correctly. Once we get an anchor, if
								// it's immediately followed by another anchor, then these must be
								// the first two characters in the string.
								// 
								// If our first anchor is not immediately followed by another
								// anchor, and the first anchor is at position zero, then we must
								// recursively call ourselves and the returned parsed part type MUST
								// be a string literal. If the position is not zero, then we
								// absolutely must not have another anchor occur later on in the
								// string, as this post-zero anchor is interpreted as an
								// end-of-request match requirement.
								// 
								// So essentially, we either need two anchors at zero followed by
								// anything but a string literal, or we need one anchor at the
								// start, with anything but an anchor, followed by an optional
								// closing anchor.

								if (cpos + 1 < max && filterStr[cpos + 1] == '|')
								{
									if (cpos != 0)
									{
										throw std::runtime_error(u8"In AbpFilterParser::ParseFilterPart(boost::string_ref&, const boost::string_ref::size_type) const - Domain anchor not at start of filter string.");
									}

									// Anchored address. We need the next string literal, this is what is being "anchored".

									auto next = ParseFilterPart(filterStr, cpos + 2);

									auto nextV = std::get<0>(next);
									auto nextT = std::get<1>(next);

									if (nextT == AbpFilter::RulePartType::StringLiteral)
									{
										if (nextV.size() > 0)
										{
											return std::make_tuple(nextV, AbpFilter::RulePartType::AnchoredAddress);
										}		

										throw std::runtime_error(u8"In AbpFilterParser::ParseFilterPart(boost::string_ref&, const boost::string_ref::size_type) const - Domain anchor followed by empty string.");
									}

									// Means we didn't get our expected string literal.
									throw std::runtime_error(u8"In AbpFilterParser::ParseFilterPart(boost::string_ref&, const boost::string_ref::size_type) const - Domain anchor followed immediately by special characters.");
								}

								if (cpos == 0)
								{
									// Address match. So we're either expecting a closing pipe, or a special character, etc. So basically,
									// we just get the next string literal.
									auto next = ParseFilterPart(filterStr, cpos + 1);

									auto nextV = std::get<0>(next);
									auto nextT = std::get<1>(next);

									if (nextT == AbpFilter::RulePartType::StringLiteral && nextV.size() > 0)
									{
										return std::make_tuple(nextV, AbpFilter::RulePartType::AddressMatch);
									}

									// Means we didn't get our expected string literal, or it was empty string.
									throw std::runtime_error(u8"In AbpFilterParser::ParseFilterPart(boost::string_ref&, const boost::string_ref::size_type) const - Address match single anchor immediately by special characters or empty string.");
								}
								else
								{
									if (cpos != (filterStr.length() - 1))
									{
										throw std::runtime_error(u8"In AbpFilterParser::ParseFilterPart(boost::string_ref&, const boost::string_ref::size_type) const - End of address anchor discovered, but anchor is not at the end of the filtering string.");
									}

									// We need a string literal to detect as the end of the request. So, if we have a previously uncollected
									// one, we'll consider this a valid closing anchor. If not, we'll throw an error. I've seen rules that have
									// a closing pipe preceded by a wildcard. This makes absolutely no sense. I don't know if ABP accepts this,
									// but it shouldn't. That's logically incoherent. ("ANY NUMBER OF CHARACTERS, THEN THE END OF THE REQUEST"). 
									// No, just no. MAYBE a separator char makes sense. XXX TODO - Investigate if we should support that.

									auto curCollected = GetCollected(collected, pos, cpos);
									collected = 0;

									if (curCollected.size() > 0)
									{
										return std::make_tuple(curCollected, AbpFilter::RulePartType::EndOfAddressMatch);
									}

									throw std::runtime_error(u8"In AbpFilterParser::ParseFilterPart(boost::string_ref&, const boost::string_ref::size_type) const - An end of address anchor should be preceded by a string literal that is to be used to detect the end of the request.");
								}
							}
							break;

							case '*':
							{
								if (collected > 0)
								{
									auto curCollected = GetCollected(collected, pos, cpos);
									collected = 0;
									if (curCollected.size() > 0)
									{
										return std::make_tuple(curCollected, AbpFilter::RulePartType::StringLiteral);
									}
								}
								else
								{
									++cpos;
									if (cpos <= max)
									{
										filterStr = filterStr.substr(cpos);
									}

									return std::make_tuple(boost::string_ref(u8"*"), AbpFilter::RulePartType::Wildcard);
								}
							}
							break;

							default:
							{
								++collected;								
							}
							break;
						}
					}

					// Rule might have been entirely a string literal match.
					if (collected > 0)
					{
						auto ss = filterStr.substr(pos, collected);
						filterStr = filterStr.substr(cpos);
						return std::make_tuple(ss, AbpFilter::RulePartType::StringLiteral);
					}
					else
					{
						throw std::runtime_error(u8"In AbpFilterParser::ParseFilterPart(boost::string_ref&, const boost::string_ref::size_type) const - Failed to parse anything. Empty string or out of bounds.");
					}
				}

				AbpFilterSettings AbpFilterParser::ParseSettings(boost::string_ref optionsString) const
				{
					AbpFilterSettings ret;

					if (optionsString.size() == 0)
					{
						return ret;
					}

					if (optionsString[0] == '$')
					{
						optionsString = optionsString.substr(1);
					}

					// Copy the stringref, as the ParseSingleOption method will consume whatever
					// we give it. Just in case, we can keep the param as an unmodified version.
					auto cpy = optionsString;

					size_t totalIgnored = 0;
					size_t totalParsed = 0;

					// While > 0 because again, ParseSingleOption is guaranteed to consume till EOF.
					while (cpy.size() > 0)
					{
						auto part = ParseSingleOption(cpy);

						if (part.size() > 0)
						{
							++totalParsed;

							const auto optionEnumResult = ValidFilterOptions.find(part);
							
							if (optionEnumResult == ValidFilterOptions.end())
							{
								++totalIgnored;
								continue;
							}

							ret.set(optionEnumResult->second, true);
						}
					}

					/*
					Do not issue a warning. This is not true, and plus the domains option is not counted here.
					if (totalIgnored > 0 && totalIgnored == totalParsed)
					{
						ReportWarning(u8"In AbpFilterParser::ParseSettings(boost::string_ref) const - All parsed rule options are unsupported. Enabling, but rule may not function correctly.");
					}
					*/

					return ret;
				}

				std::unordered_set<size_t> AbpFilterParser::ParseDomains(boost::string_ref optionsString, const bool exceptions) const
				{
					std::unordered_set<size_t> ret;

					if (optionsString.size() == 0)
					{
						// We default to no exception domains.
						return ret;
					}

					if (optionsString[0] == '$')
					{
						optionsString = optionsString.substr(1);
					}

					boost::string_ref domainsOpt(u8"domain=");
					auto domainsPartSize = domainsOpt.size();

					// Copy the stringref, as the ParseSingleOption method will consume whatever
					// we give it. Just in case, we can keep the param as an unmodified version.
					auto cpy = optionsString;

					boost::string_ref domainsPart;

					// While > 0 because again, ParseSingleOption is guaranteed to consume till EOF.
					while (cpy.size() > 0)
					{
						auto part = ParseSingleOption(cpy);
						
						if (part.size() > domainsPartSize && part.substr(0, domainsOpt.size()).compare(domainsOpt) == 0)
						{
							domainsPart = part.substr(domainsPartSize);
							break;
						}
					}

					// Proceed if the domains option was discovered.
					if (domainsPart.size() > 0)
					{
						// Multiple domains in the option are split with a single pipe char.
						auto pipePos = domainsPart.find('|');

						while (pipePos != boost::string_ref::npos)
						{
							auto domain = domainsPart.substr(0, pipePos);
							domainsPart = domainsPart.substr(pipePos + 1);
							pipePos = domainsPart.find('|');

							if (domain.size() == 0)
							{
								throw std::runtime_error(u8"In AbpFilterParser::ParseDomains(boost::string_ref&, const bool) const - Incorrectly formatted domain option entry. Zero length.");
							}

							// If its an exception and user asked for exception, if its not exception and user asked
							// for non-exceptins, etc. Only insert what the user is asking for.
							bool shouldInsert = (exceptions == (domain[0] == '~'));

							if (shouldInsert)
							{
								// Remove the exception indicator character if applicable.
								if (exceptions)
								{
									domain = domain.substr(1);
								}
								
								ret.insert(util::string::Hash(domain));
							}
						}

						// The previous loop will have consumed domain list if one was found, and left the final
						// entry. Or, if no list was found, we'll still have a single entry and this condition
						// will be true.
						if (domainsPart.size() > 0)
						{
							// Single domain entry. 

							// If its an exception and user asked for exception, if its not exception and user asked
							// for non-exceptins, etc. Only insert what the user is asking for.
							bool shouldInsert = (exceptions == (domainsPart[0] == '~'));

							if (shouldInsert)
							{
								// Remove the exception indicator character if applicable.
								if (exceptions)
								{
									domainsPart = domainsPart.substr(1);
								}

								ret.insert(util::string::Hash(domainsPart));
							}
						}
					}

					// We don't want this at all. We simply want an empty list if there are no
					// inclusion domains, since we simply check for domain existence during the
					// matching process only when the inclusion domain list has a count greater
					// than zero.
					//if (ret.size() == 0 && !exceptions)
					//{
					//	// Default for non-exception domains is to have global inclusion.
					//	ret.insert(u8"*");
					//}

					return ret;
				}

				boost::string_ref AbpFilterParser::ParseSingleOption(boost::string_ref& optionsString) const
				{
					if (optionsString.size() == 0)
					{
						return optionsString;
					}

					auto commaPos = optionsString.find(',');

					if (commaPos != boost::string_ref::npos)
					{
						auto ret = optionsString.substr(0, commaPos);
						optionsString = optionsString.substr(commaPos + 1);

						return ret;
					}

					auto ret = optionsString;
					optionsString = boost::string_ref();

					return ret;
				}

			} /* namespace http */
		} /* namespace filtering */
	} /* namespace httpengine */
} /* namespace te */
