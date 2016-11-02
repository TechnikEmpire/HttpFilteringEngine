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

#include "HttpFilteringEngine.hpp"
#include <stdexcept>
#include <fstream>
#include <boost/algorithm/string.hpp>
#include <boost/thread.hpp>
#include "../../mitm/http/HttpRequest.hpp"
#include "../../mitm/http/HttpResponse.hpp"
#include "../options/ProgramWideOptions.hpp"
#include "../../../util/http/KnownHttpHeaders.hpp"
#include "CategorizedCssSelector.hpp"
#include <algorithm>
#include <cctype>

//#include "AbpFilterParser.hpp"

#include <Document.hpp>
#include <NodeMutationCollection.hpp>
#include <Serializer.hpp>

namespace te
{
	namespace httpengine
	{
		namespace filtering
		{
			namespace http
			{				
				
				HttpFilteringEngine::HttpFilteringEngine(
					const options::ProgramWideOptions* programOptions,
					util::cb::MessageFunction onInfo,
					util::cb::MessageFunction onWarn,
					util::cb::MessageFunction onError,
					util::cb::ContentClassificationFunction onClassify,
					util::cb::RequestBlockFunction onRequestBlocked,
					util::cb::ElementBlockFunction onElementsBlocked
					) :
					util::cb::EventReporter(
						onInfo, 
						onWarn, 
						onError
						),
					m_programOptions(programOptions),
					m_onClassifyContent(onClassify),
					m_onRequestBlocked(onRequestBlocked),
					m_onElementsBlocked(onElementsBlocked)
				{					
					#ifndef NDEBUG
						assert(programOptions != nullptr && u8"In HttpFilteringEngine::HttpFilteringEngine(const options::ProgramWideOptions*, TextClassificationCallback) - ProgramWideOptions pointer must not be null. Options must exist and be available for the lifetime of the program for the software to function correctly.");
					#else
						if (programOptions == nullptr) { throw std::runtime_error(u8"In HttpFilteringEngine::HttpFilteringEngine(const options::ProgramWideOptions*, TextClassificationCallback) - ProgramWideOptions pointer must not be null. Options must exist and be available for the lifetime of the program for the software to function correctly."); };
					#endif					
				}

				HttpFilteringEngine::~HttpFilteringEngine()
				{

				}

				std::pair<uint32_t, uint32_t> HttpFilteringEngine::LoadAbpFormattedListFromFile(
					const std::string& listFilePath, 
					const uint8_t listCategory, 
					const bool flushExistingRules
					)
				{
					std::ifstream in(listFilePath, std::ios::binary | std::ios::in);

					if (in.fail() || in.is_open() == false)
					{					
						std::string errMessage(u8"In HttpFilteringEngine::LoadAbpFormattedListFromFile(const std::string&, const uint8_t, const bool) - Unable to read supplied filter list file: " + listFilePath);
						ReportError(errMessage);
						return { 0, 0 };
					}

					std::string listContents;
					in.seekg(0, std::ios::end);

					auto fsize = in.tellg();

					if (fsize < 0 || static_cast<unsigned long long>(fsize) > static_cast<unsigned long long>(std::numeric_limits<size_t>::max()))
					{
						ReportError(u8"In HttpFilteringEngine::LoadAbpFormattedListFromFile(const std::string&, const uint8_t, const bool) - When loading file, ifstream::tellg() returned either less than zero or a number greater than this program can correctly handle.");
						return { 0, 0 };
					}

					listContents.resize(static_cast<size_t>(fsize));
					in.seekg(0, std::ios::beg);
					in.read(&listContents[0], listContents.size());
					in.close();

					return LoadAbpFormattedListFromString(listContents, listCategory, flushExistingRules);
				}

				std::pair<uint32_t, uint32_t> HttpFilteringEngine::LoadAbpFormattedListFromString(
					const std::string& list, 
					const uint8_t listCategory, 
					const bool flushExistingRules
					)
				{
					uint32_t succeeded = 0;
					uint32_t failed = 0;					

					if (flushExistingRules)
					{
						// If flushExistingRules is true, remove all existing filters from all containers that match the specified
						// category for the list. Make sure to respect this ordering, because UnloadAllFilterRulesForCategory acquires a
						// writer lock.
						UnloadAllFilterRulesForCategory(listCategory);
					}

					// Must come after unloading all rules, since UnloadAllFilterRulesForCategory acquires write lock as well.
					Writer w(m_filterLock);

					std::istringstream f(list);
					std::string line;
					while (std::getline(f, line))
					{
						if (!ProcessAbpFormattedRule(line, listCategory))
						{
							// We don't really want to throw the whole operation out if there is
							// some issue with a single filtering rule. Instead, we return false to
							// let the user know that something undesirable did take place, but
							// carry on if possible. The user should be subscribed to the various
							// events provided through the EventReporter interface to get more
							// meaningful information about exactly what went wrong.
							++failed;
							continue;
						}

						++succeeded;
					}

					return { succeeded, failed };
				}

				uint32_t HttpFilteringEngine::LoadTextTriggersFromFile(const std::string& triggersFilePath, const uint8_t category, const bool flushExisting)
				{
					std::ifstream in(triggersFilePath, std::ios::binary | std::ios::in);

					if (in.fail() || in.is_open() == false)
					{
						std::string errMessage(u8"In HttpFilteringEngine::LoadTextTriggersFromFile(const std::string&, const uint8_t, const bool) - Unable to read supplied filter list file: " + triggersFilePath);
						ReportError(errMessage);
						return 0;
					}

					std::string listContents;
					in.seekg(0, std::ios::end);

					auto fsize = in.tellg();

					if (fsize < 0 || static_cast<unsigned long long>(fsize) > static_cast<unsigned long long>(std::numeric_limits<size_t>::max()))
					{
						ReportError(u8"In HttpFilteringEngine::LoadTextTriggersFromFile(const std::string&, const uint8_t, const bool) - When loading file, ifstream::tellg() returned either less than zero or a number greater than this program can correctly handle.");
						return 0;
					}

					listContents.resize(static_cast<size_t>(fsize));
					in.seekg(0, std::ios::beg);
					in.read(&listContents[0], listContents.size());
					in.close();

					return LoadTextTriggersFromString(listContents, category, flushExisting);
				}

				uint32_t HttpFilteringEngine::LoadTextTriggersFromString(const std::string& triggers, const uint8_t category, const bool flushExisting)
				{
					return 0;
					if (flushExisting)
					{
						UnloadAllTextTriggersForCategory(category);
					}

					// Claim writer AFTER UnloadAllTextTriggersForCategory because it claims a writer itself.
					Writer w(m_filterLock);

					uint32_t loadedRulesCount = 0;

					std::istringstream f(triggers);
					std::string line;
					while (std::getline(f, line))
					{
						// Ensure this isn't just whitespace.
						boost::trim(line);
						if (line.size() > 0)
						{
							auto preserved = util::string::Hash(boost::string_ref(line));//GetPreservedICaseStringRef(boost::string_ref(line));

							// We simply assign or insert. It's up to list maintainers to make sure that
							// they're not overlapping their own rules.
							m_domainRequestBlacklist[preserved] = category;
							//m_textTriggers[preserved] = category;
							
							++loadedRulesCount;
						}
					}

					return loadedRulesCount;
				}

				void HttpFilteringEngine::UnloadAllFilterRulesForCategory(const uint8_t category)
				{
					
					Writer w(m_filterLock);

					auto it = m_domainRequestBlacklist.begin();

					while(it != m_domainRequestBlacklist.end())
					{
						if (it->second == category)
						{
							it = m_domainRequestBlacklist.erase(it);
						}
						else
						{
							++it;
						}
					}

					it = m_domainRequestWhitelist.begin();

					while (it != m_domainRequestWhitelist.end())
					{
						if (it->second == category)
						{
							it = m_domainRequestWhitelist.erase(it);
						}
						else
						{
							++it;
						}
					}

					for (auto& selectorPair : m_inclusionSelectors)
					{
						selectorPair.second.erase(std::remove_if(selectorPair.second.begin(), selectorPair.second.end(),
							[category](const SharedCategorizedCssSelector& s) -> bool
						{
							return s->GetCategory() == category;
						}), selectorPair.second.end());
					}

					for (auto& selectorPair : m_exceptionSelectors)
					{
						selectorPair.second.erase(std::remove_if(selectorPair.second.begin(), selectorPair.second.end(),
							[category](const SharedCategorizedCssSelector& s) -> bool
						{
							return s->GetCategory() == category;
						}), selectorPair.second.end());
					}
				}

				void HttpFilteringEngine::UnloadAllTextTriggersForCategory(const uint8_t category)
				{
					/*
					Writer w(m_filterLock);

					// Remove all entries where the category is the same.
					auto it = m_textTriggers.begin();
					while (it != m_textTriggers.end())
					{
						if (it->second == category)
						{
							it = m_textTriggers.erase(it);
						}
						else
						{
							++it;
						}
					}
					*/
				}

				uint8_t HttpFilteringEngine::ShouldBlock(const mhttp::HttpRequest* request, mhttp::HttpResponse* response, const bool isSecure)
				{
					#ifndef NDEBUG
						assert(request != nullptr && u8"In HttpFilteringEngine::ShouldBlock(mhttp::HttpRequest*, mhttp::HttpResponse*) - The HttpRequest parameter was supplied with a nullptr. The request is absolutely required to do accurate HTTP filtering.");
					#else // !NDEBUG
						if (request == nullptr)
						{
							throw std::runtime_error(u8"In HttpFilteringEngine::ShouldBlock(mhttp::HttpRequest*, mhttp::HttpResponse*) - The HttpRequest parameter was supplied with a nullptr. The request is absolutely required to do accurate HTTP filtering.");
						}
					#endif					

					try
					{
						// If the request is already set to be blocked, and the response is supplied,
						// then we simply want to report the size of the blocked content from the 
						// response headers before actually downloading all of the response.
						if (request != nullptr && request->GetShouldBlock() != 0)
						{
							auto blockCategory = request->GetShouldBlock();

							ReportRequestBlocked(request, response);
							return blockCategory;
						}

						if (response != nullptr && response->GetShouldBlock() != 0)
						{
							auto blockCategory = response->GetShouldBlock();

							ReportRequestBlocked(request, response);
							return blockCategory;
						}

						// XXX TODO - Check if the specified host is just an IP address and if so, reverse resolve the domain name.
						boost::string_ref hostStringRef;

						// The simplest form of blocking is domain blacklisting, so if the request has
						// been supplied here, then extract the host and check to see if it is a
						// blacklisted host. Of course before doing so, check to see if the host is
						// whitelisted, meaning no processing by this engine should be done against
						// content to or from the specified host.
						auto hostHeaders = request->GetHeader(util::http::headers::Host);

						if (hostHeaders.first != hostHeaders.second)
						{
							hostStringRef = boost::string_ref(hostHeaders.first->second);
						}

						hostStringRef = ExtractHostNameFromUrl(hostStringRef);

						// Before going any further, we must verify that the extractedHost is not empty. If it is, then
						// we can't do a whole lot with this because the http request is fundamentally broken.
						if (hostStringRef.size() == 0)
						{
							ReportWarning(u8"In HttpFilteringEngine::ShouldBlock(mhttp::HttpRequest*, mhttp::HttpResponse*) - Host declaration is missing from the HTTP request. As the request is fundamentally broken, aborting any further analysis.");
							return 0;
						}

						Reader r(m_filterLock);

						auto hostStringRefHashed = util::string::Hash(hostStringRef);

						if (m_domainRequestWhitelist.find(hostStringRefHashed) != m_domainRequestWhitelist.end())
						{
							// Whitelisted domain.
							return 0;
						}

						std::string fullRequest{ isSecure ? u8"https://" : u8"http://" };
						fullRequest.append(hostStringRef.to_string()).append(u8"/").append(request->RequestURI());

						std::string fullRequestNoScheme{ hostStringRef.to_string().append(u8"/").append(request->RequestURI()) };

						auto fullRequestHashed = util::string::Hash(boost::string_ref(fullRequest));
						auto fullRequestNoSchemeHashed = util::string::Hash(boost::string_ref(fullRequestNoScheme));

						if (m_domainRequestWhitelist.find(fullRequestNoSchemeHashed) != m_domainRequestWhitelist.end() || m_domainRequestWhitelist.find(fullRequestHashed) != m_domainRequestWhitelist.end())
						{
							// Whitelisted request.
							return 0;
						}

						auto blSearch = m_domainRequestBlacklist.find(hostStringRefHashed);

						if (blSearch != m_domainRequestBlacklist.end() && m_programOptions->GetIsHttpCategoryFiltered(blSearch->second))
						{
							// Blacklisted domain.
							ReportRequestBlocked(request, response);
							ReportInfo("Blocked by host string ref hashed.");							
							return blSearch->second;
						}

						blSearch = m_domainRequestBlacklist.find(fullRequestNoSchemeHashed);

						if (blSearch != m_domainRequestBlacklist.end() && m_programOptions->GetIsHttpCategoryFiltered(blSearch->second))
						{
							// Blacklisted request.
							ReportRequestBlocked(request, response);
							ReportInfo("Blocked by full req with no scheme.");
							return blSearch->second;
						}

						blSearch = m_domainRequestBlacklist.find(fullRequestHashed);

						if (blSearch != m_domainRequestBlacklist.end() && m_programOptions->GetIsHttpCategoryFiltered(blSearch->second))
						{
							// Blacklisted request.
							ReportRequestBlocked(request, response);
							ReportInfo("Blocked by full request hashed.");
							return blSearch->second;
						}

						// Last thing to do, since we've decided not to block here, is to see if the
						// response is not complete. If it is not yet complete, and the response headers
						// declare types of data we are capable of inspecting, we want to go ahead and
						// flag those responses to have them entirely consumed in-memory (where limits
						// allow). This way we'll get the responses give back to use here inside of
						// ShouldBlock to be checked again.
						if (response != nullptr)
						{
							if (response->IsPayloadComplete() == false)
							{
								// Force the payload to be downloaded.
								if (response->IsPayloadText())
								{
									// We want to consume JSON responses. By consuming them to the end, the ShouldBlock
									// method on the Engine will pass it off to the content classification callback if
									// it's available. Porn results can be caught this way.

									// We filter with CSS filters, so we want to consume entire HTML responses before
									// sending them back to the client, so we can filter them first.
									response->SetConsumeAllBeforeSending(true);
								}
							}
							else
							{
								if (response->IsPayloadCompressed())
								{
									if (!response->DecompressPayload())
									{
										ReportWarning(u8"In HttpFilteringEngine::ShouldBlock(...) - Failed to decompress payload, cannot inspect.");
										return 0;
									}
								}

								// Get a reference to the response payload.
								const auto& payload = response->GetPayload();

								if (response->IsPayloadText())
								{
									// This will include JSON, XML, HTML, etc.
									//ReportInfo(u8"Checking json or text payload for triggers.");
									//ReportInfo(fullRequest);
									auto shouldBlockDueToTextTrigger = ShouldBlockBecauseOfTextTrigger(payload);

									if (shouldBlockDueToTextTrigger != 0)
									{
										// Report block action because we have a response. Whenever we have a response in
										// this context, it's our last chance to report on the transaction before
										// it is terminated.
										ReportRequestBlocked(request, response);
										ReportInfo("Blocked by text trigger.");
										return shouldBlockDueToTextTrigger;
									}
								}

								// The very last thing we can check if we made it here, is to see if we have content
								// that we can classify. Check if we have an external classification callback.
								if (m_onClassifyContent)
								{
									//ReportInfo(u8"Checking for content classification.");
									//ReportInfo(fullRequest);

									// Default to an empty aka unknown string for content type;
									std::string contentTypeString;
									auto contentTypeHeader = response->GetHeader(util::http::headers::ContentType);

									if (contentTypeHeader.first != contentTypeHeader.second)
									{
										contentTypeString = contentTypeHeader.first->second;
									}

									if (contentTypeString.size() == 0)
									{
										contentTypeString = std::string(u8"unknown");
									}

									// Pass over the content for classification.
									uint8_t contentClassResult = m_onClassifyContent(payload.data(), payload.size(), contentTypeString.c_str(), contentTypeString.size());

									if (contentClassResult != 0 && m_programOptions->GetIsHttpCategoryFiltered(contentClassResult))
									{
										// Report block action because we have a response. Whenever we have a response in
										// this context, it's our last chance to report on the transaction before
										// it is terminated.
										ReportRequestBlocked(request, response);
										ReportInfo("Blocked by content classification.");
										return contentClassResult;
									}
								}

								// We're not blocking, so last thing to do is run selectors if payload is HTML.
								// We'll only do this though if we actually have selectors. No sense in
								// parsing the HTML if we don't.
								if (response->IsPayloadHtml() && (m_inclusionSelectors.size() > 0 || m_exceptionSelectors.size() > 0))
								{
									// Payload is complete, it's HTML, and it was kept for further inspection. Let the CSS selectors
									// rip through the HTML payload before returning.
									auto processedHtmlString = this->ProcessHtmlResponse(request, response);

									if (processedHtmlString.size() > 0)
									{
										std::vector<char> processedHtmlVector(processedHtmlString.begin(), processedHtmlString.end());
										response->SetPayload(std::move(processedHtmlVector));
									}
								}
							}
						}
					}
					catch(std::exception& e)
					{
						// This would only happen, AFAIK, if we failed to parse any valid HTML.
						std::string errMessage(u8"In HttpFilteringEngine::ShouldBlock(...) const - Error:\t");
						errMessage.append(e.what());
						ReportError(errMessage);
					}

					// No matches of any kind were found, so the transaction should be allowed to complete.
					return 0;
				}				

				std::string HttpFilteringEngine::ProcessHtmlResponse(const mhttp::HttpRequest* request, const mhttp::HttpResponse* response)
				{
					#ifndef NDEBUG
						assert(request != nullptr && response != nullptr && u8"In HttpFilteringEngine::ProcessHtmlResponse(const mhttp::HttpRequest*, const mhttp::HttpResponse*) const - The HttpRequest or HttpResponse parameter was supplied with a nullptr. Both are absolutely required to be valid to accurately filter html payloads.");
					#else // !NDEBUG
						if (request == nullptr || response == nullptr)
						{
							throw std::runtime_error(u8"In HttpFilteringEngine::ProcessHtmlResponse(const mhttp::HttpRequest*, const mhttp::HttpResponse*) const - The HttpRequest or HttpResponse parameter was supplied with a nullptr. Both are absolutely required to be valid to accurately filter html payloads.");
						}
					#endif

					// XXX TODO need to support use of the $document $~document filtering rules.

					if (!response->IsPayloadComplete() || !response->GetConsumeAllBeforeSending())
					{
						// I should destroy the universe for you giving me an incomplete or partial
						// transaction. But, I'll spare you.
						return std::string();
					}

					bool isPayloadText = response->IsPayloadText();
					bool isPayloadHtml = response->IsPayloadHtml();

					if (!isPayloadText || !isPayloadHtml)
					{
						// We can't attempt to parse this as HTML when the content type doesn't even come close.
						return std::string();
					}

					// So, if the payload is described as text, it may well be valid HTML. It may
					// also be some mess of mixed up data with embedded HTML. We can't be certain.
					// So, we'll just take a full stride run at parsing and filtering, and if we
					// succeed, we'll check the offsets of the document start and end. If the
					// offsets don't start at zero and end at the payload end, then we'll try to put
					// humpty-dumpty back together again. #yolo.

					auto doc = gq::Document::Create();

					const auto& payloadVector = response->GetPayload();

					boost::string_ref payloadStrRef(payloadVector.data(), payloadVector.size());
					auto payloadString = payloadStrRef.to_string();

					try
					{	
						doc->Parse(payloadString);
					}
					catch (std::runtime_error& e)
					{						
						// This would only happen, AFAIK, if we failed to parse any valid HTML.
						std::string errMessage(u8"In HttpFilteringEngine::ProcessHtmlResponse(const mhttp::HttpRequest*, const mhttp::HttpResponse*) const - Error:\t");
						errMessage.append(e.what());
						ReportError(errMessage);
						return std::string();
					}

					// Where we're going to collect all matched nodes.
					gq::NodeMutationCollection collection;		

					// Reader lock.
					Reader r(m_filterLock);

					// We'll start out getting global selectors and running them against the
					// document, collecting all results into the NodeMutationCollection structure.
					const auto& globalIncludeSelectors = m_inclusionSelectors.find(m_globalRuleKeyHashed);

					if (globalIncludeSelectors != m_inclusionSelectors.end())
					{
						for (const auto& selector : globalIncludeSelectors->second)
						{
							if (m_programOptions->GetIsHttpCategoryFiltered(selector->GetCategory()))
							{
								doc->Each(selector->GetSelector(),
									[&collection](const gq::Node* node)->void
								{
									collection.Add(node);
								});
							}							
						}
					}

					// Try to get the host information from the request.
					boost::string_ref hostStringRef;
					auto hostStringRefHashed = util::string::Hash(hostStringRef);
					auto hostHeaders = request->GetHeader(util::http::headers::Host);

					if (hostHeaders.first != hostHeaders.second)
					{
						hostStringRef = boost::string_ref(hostHeaders.first->second);
					}

					// If we got host information, we'll move to host specific selectors and collect
					// all results in the same collection.
					if (hostStringRef.size() > 0)
					{
						const auto& hostIncludeSelectors = m_inclusionSelectors.find(hostStringRefHashed);

						if (hostIncludeSelectors != m_inclusionSelectors.end())
						{
							for (const auto& selector : hostIncludeSelectors->second)
							{
								if (m_programOptions->GetIsHttpCategoryFiltered(selector->GetCategory()))
								{
									doc->Each(selector->GetSelector(),
										[&collection](const gq::Node* node)->void
									{
										collection.Add(node);
									});
								}								
							}
						}

						// Now we have collected every possible element for removal, it's time to
						// prune down the collection with whitelist selectors. Start with host specific
						// while we're in this scope.

						const auto& hostExcludeSelectors = m_exceptionSelectors.find(hostStringRefHashed);

						if (hostExcludeSelectors != m_exceptionSelectors.end())
						{
							for (const auto& selector : hostExcludeSelectors->second)
							{
								if (m_programOptions->GetIsHttpCategoryFiltered(selector->GetCategory()))
								{
									doc->Each(selector->GetSelector(),
										[&collection](const gq::Node* node)->void
									{
										collection.Remove(node);
									});
								}
							}
						}
					}

					// Now we'll run global whitelist selectors and prune our results further.
					const auto& globalExceptionSelectors = m_exceptionSelectors.find(m_globalRuleKeyHashed);

					if (globalExceptionSelectors != m_exceptionSelectors.end())
					{
						for (const auto& selector : globalExceptionSelectors->second)
						{
							if (m_programOptions->GetIsHttpCategoryFiltered(selector->GetCategory()))
							{

								doc->Each(selector->GetSelector(),
									[&collection](const gq::Node* node)->void
								{
									collection.Remove(node);
								});
							}
						}
					}

					

					// Report numberOfHtmlElementsRemoved
					if (collection.Size() > 0)
					{
						std::string fullRequestString = hostStringRef.to_string();
						fullRequestString += request->RequestURI();
						ReportElementsBlocked(static_cast<uint32_t>(collection.Size()), fullRequestString);
					}					

					// Now we can serialize the result, removing our final collection of nodes.
					auto serialized = gq::Serializer::Serialize(doc.get(), &collection);

					std::string finalResult;

					auto docStartPos = doc->GetStartOuterPosition();
					auto docEndPos = doc->GetEndOuterPosition();

					// As mentioned earlier in the comments, we might have got some valid HTML that
					// was embedded in some other unknown data. So, we'll check the
					// doc->GetStartOuterPosition() and doc->GetEndOuterPosition(), then copy the
					// difference in offsets onto the serialized string and return it. This way,
					// we're not blowing away any data we shouldn't be.
					if (docStartPos > 0)
					{
						finalResult.append(payloadStrRef.substr(0, docStartPos).to_string());
					}

					finalResult.append(serialized);

					if (docEndPos < (payloadStrRef.size() - 1))
					{
						finalResult.append(payloadStrRef.substr(docEndPos + 1).to_string());
					}

					return finalResult;
				}

				void HttpFilteringEngine::FinalizeBlockedResponse(mhttp::HttpResponse* response) const
				{
					if (response == nullptr)
					{
						return;
					}

					bool handled = false;
					
					if (response->IsPayloadHtml())
					{
						auto userDefinedHtmlBlockedPage = m_programOptions->GetHtmlBlockedPagePayload();

						if (userDefinedHtmlBlockedPage.size() > 0)
						{
							response->SetPayload(userDefinedHtmlBlockedPage);
							handled = true;
						}
					}

					if (!handled)
					{
						response->Make204();
					}
				}

				uint8_t HttpFilteringEngine::ShouldBlockBecauseOfTextTrigger(const std::vector<char>& payload) const
				{	

					boost::string_ref content = boost::string_ref(payload.data(), payload.size());

					auto collect = [content]() -> std::vector<boost::string_ref>
					{
						std::vector<boost::string_ref> ret;

						boost::string_ref::size_type start = 0, end = 0;
						auto len = content.size();

						for (auto i = 0; i < len; ++i)
						{
							auto c = static_cast<unsigned char>(content[i]);

							if (std::isalnum(c) || (content[i] == '.' || content[i] == '-'))
							{
								++end;
								continue;
							}

							if (start < len && (end - start) > start && (start + (end - start)) < len)
							{
								ret.emplace_back(content.substr(start, end - start));
							}

							start = i + 1;
							end = i + 1;
						}

						return ret;
					};

					auto toCheck = collect();

					for (auto entry : toCheck)
					{
						auto hashedEntry = util::string::Hash(entry);

						// Try and find the match candidate in the triggers map.
						auto match = m_domainRequestBlacklist.find(hashedEntry);

						if (match != m_domainRequestBlacklist.end())
						{
							// If the trigger is both found and the match category is enabled, and it's not whitelisted,
							// just return the found category.
							if (m_domainRequestWhitelist.find(hashedEntry) == m_domainRequestWhitelist.end() && m_programOptions->GetIsHttpCategoryFiltered(match->second))
							{
								ReportInfo(entry);
								return match->second;
							}
						}

						// Now we're going to widdle down this match in case we find a subdomain that is blocked
						// For example, this match might presently be www.somethingbad.com, where we only have
						// somethingbad.com in our lists. So, we're gonna chop it down till there's nothing
						// left looking for a match.
						auto subDomainIndicator = entry.find('.');

						while (subDomainIndicator != boost::string_ref::npos && subDomainIndicator + 1 < entry.size())
						{
							entry = entry.substr(subDomainIndicator + 1);
							hashedEntry = util::string::Hash(boost::string_ref(entry));
							match = m_domainRequestBlacklist.find(hashedEntry);

							if (match != m_domainRequestBlacklist.end())
							{
								// If the trigger is both found and the match category is enabled, and it's not whitelisted,
								// just return the found category.
								if (m_domainRequestWhitelist.find(hashedEntry) == m_domainRequestWhitelist.end() && m_programOptions->GetIsHttpCategoryFiltered(match->second))
								{
									ReportInfo(entry);
									return match->second;
								}
							}

							subDomainIndicator = entry.find('.');
						}
					}

					return 0;
				}

				uint8_t HttpFilteringEngine::ShouldBlockHost(boost::string_ref hostname)
				{
					// XXX TODO - This can be improved later to factor in the full request
					// string, but for now we're looking to block non-http requests by
					// just the host name.

					if(!hostname.data() || hostname.size() == 0 )
					{
						// No valid data supplied.
						return 0;
					}

					Reader r(m_filterLock);

					auto hostStringRefHashed = util::string::Hash(hostname);

					if (m_domainRequestWhitelist.find(hostStringRefHashed) != m_domainRequestWhitelist.end())
					{
						// Whitelisted domain.
						return 0;
					}

					auto blSearch = m_domainRequestBlacklist.find(hostStringRefHashed);

					if (blSearch != m_domainRequestBlacklist.end() && m_programOptions->GetIsHttpCategoryFiltered(blSearch->second))
					{
						// Blacklisted domain.						
						ReportInfo("Blocked by host string ref hashed.");
						ReportInfo(hostname);
						return blSearch->second;
					}

					return 0;
				}

				bool HttpFilteringEngine::ProcessAbpFormattedRule(const std::string& rule, const uint8_t category)
				{
					// Can't do much with an empty line, but this isn't an error.
					if (rule.size() == 0)
					{
						return true;
					}

					// This is a comment line in an ABP filter list.
					if (rule[0] == '!' || rule[0] == '[')
					{
						return true;
					}

					// Check if the rule is a global selector
					if (rule.size() >= 3 && (rule[0] == '#' && rule[2] == '#'))
					{
						// This is a global selector rule, not bound to a domain. Every single selector rule begins with a '#' 
						// which is used strictly to indicate a selector rule, and the first '#' must be ignored.
						// The second character indicates if the selector if an exception or not. If the second character is a
						// the char '@', then the selector is meant for whitelisting. If the second character is a '#' char, then
						// the rule is meant for blacklisting. The third character in the sequence should always be a '#' char,
						// and all following characters are literal parts of the selector string. The fourth char may be a '.'
						// in a class selector, or a '#' in an ID selector. If neither, then it's almost definitely a tag selector.
						//
						// Beyond this point, we don't need to concern ourselves. The selector engine will deal with that. We just
						// need to trim off the special characters that the ABP syntax adds to the selectors.

						bool exception = (rule[1] == '@');
						AddSelectorMultiDomain(m_globalRuleKey, rule.substr(2), category, exception);
						return true;
					}
					else
					{
						// Note that this rule could still be a selector, but it would be bound to a specific domain. If
						// either of these strings are found, then it is a selection filter and the text preceeding these
						// matches is either a single domain or multiple domains separated by commas.
						auto selectorStartPosition = rule.find(u8"##");	

						if (selectorStartPosition == std::string::npos)
						{
							selectorStartPosition = rule.find(u8"#@");
						}
						
						if (selectorStartPosition != std::string::npos && (selectorStartPosition + 3 < rule.size()))
						{
							boost::string_ref domains = boost::string_ref(rule.c_str(), selectorStartPosition);

							// This is a selector rule with domain information attached.

							if (rule[selectorStartPosition + 1] == '@')
							{
								// Exception selector that is domain specific. Note we cut at 3 here, instead of 2. This is
								// because it's a domain-specific exception selector. Exception selectors that are domain
								// specific employ a unique format, in that the "actual" selector string is preceeded by
								// #@## instead of simply #@. So a class selector would look like #@#.
								AddSelectorMultiDomain(m_globalRuleKey, rule.substr(selectorStartPosition + 3), category, true);
								return true;
							}
							else if(rule[selectorStartPosition + 1] == '#')
							{
								// Inclusion selector that is domain specific. In constrast to the domain specific exception
								// selectors, the inclusion selectors (elements that should be hidden) follow the same syntax
								// as global selectors. That is, they are preceeded by only 2 padding characters, "##". So
								// a domain specific class selector would look like ##.class, so we trim at pos 2.
								AddSelectorMultiDomain(m_globalRuleKey, rule.substr(selectorStartPosition + 2), category);
								return true;
							}
						}
						else
						{
							// Means we got a selector rule but the bounds were not sufficient.
							if (selectorStartPosition != std::string::npos)
							{
								ReportWarning(u8"In HttpFilteringEngine::ProcessAbpFormattedRule(const std::string&, const uint8_t) - Selector rule key '#' found but was at end of rule string bounds. Ignoring.");
								return false;
							}

							// This is a filtering rule.

							std::string extractedRule = rule;

							boost::trim(extractedRule);

							if (extractedRule.size() > 0)
							{
								if (extractedRule[0] == '/' && extractedRule[extractedRule.size() - 1] == '/')
								{
									// This is a regex rule. We don't want these. I believe there's only one regex
									// rule left inside of the ABP EasyList at the time of this writing.
									return false;
								}

								try
								{
									if (extractedRule.size() > 2)
									{
										std::transform(extractedRule.begin(), extractedRule.end(), extractedRule.begin(), ::tolower);
										if (extractedRule[0] == '@' && extractedRule[1] == '@')
										{
											extractedRule = extractedRule.substr(2);											
											m_domainRequestWhitelist[util::string::Hash(boost::string_ref(extractedRule))] = category;
											return true;
										}
										else
										{
											m_domainRequestBlacklist[util::string::Hash(boost::string_ref(extractedRule))] = category;
											return true;
										}
									}									
								
									return false;
								}
								catch (std::runtime_error& pErr)
								{
									std::string unhandledErrMsg(u8"In HttpFilteringEngine::ProcessAbpFormattedRule(const std::string&, const uint8_t) - Got error: ");
									unhandledErrMsg.append(pErr.what());
									ReportError(unhandledErrMsg);
									return false;
								}								

								return true;
							}
						}
					}

					// How did we not handle this rule??
					std::string unhandledErrMsg(u8"In HttpFilteringEngine::ProcessAbpFormattedRule(const std::string&, const uint8_t) - Unhandled filtering rule was ignored: ");
					unhandledErrMsg.append(rule);
					ReportError(unhandledErrMsg);
					return false;
				}

				void HttpFilteringEngine::AddSelectorMultiDomain(
					boost::string_ref domains, 
					const std::string& selector, 
					const uint8_t category, 
					const bool isException
					)
				{
					
					SharedCategorizedCssSelector sSelector = nullptr;

					try
					{
						sSelector = std::make_shared<CategorizedCssSelector>(domains, selector, category);
					}
					catch (std::runtime_error& e)
					{
						std::string errMsg(u8"In HttpFilteringEngine::AddSelectorMultiDomain(boost::string_ref, const std::string&, const uint8_t) Error:\t");
						errMsg.append(e.what());
						ReportError(errMsg);
						return;
					}					

					#ifndef NDEBUG
						assert(sSelector != nullptr && u8"In HttpFilteringEngine::AddSelectorMultiDomain(boost::string_ref, const std::string&, const uint8_t) - Failed to allocate shared selector.");
					#else // !NDEBUG
						if (sSelector == nullptr)
						{
							throw std::runtime_error(u8"In HttpFilteringEngine::AddSelectorMultiDomain(boost::string_ref, const std::string&, const uint8_t) - Failed to allocate shared selector.");
						}
					#endif					

					char delim = 0;

					if (domains.find(',') != boost::string_ref::npos)
					{
						// Multiple domains supplied, separated by commas
						delim = ',';
					}
					else if (domains.find('|') != boost::string_ref::npos)
					{
						// Multiple domains supplied, separated by pipes
						delim = '|';
					}

					if (delim == 0)
					{
						// Single domain supplied, may also be m_globalRuleKey aka "*". Doesn't matter, treated the same. 
						if (isException)
						{
							AddExceptionSelector(domains, sSelector);
						}
						else
						{
							AddIncludeSelector(domains, sSelector);							
						}						
					}
					else
					{
						// Multi domain
						auto domainsVector = util::string::Split(domains, delim);
						
						for(auto domain : domainsVector)
						{
							if (isException)
							{
								AddExceptionSelector(domain, sSelector);
							}
							else
							{
								AddIncludeSelector(domain, sSelector);
							}
						}
					}
				}				

				void HttpFilteringEngine::AddIncludeSelector(boost::string_ref domain, const SharedCategorizedCssSelector& selector)
				{
					auto domainStored = util::string::Hash(boost::string_ref(domain));

					const auto& i = m_inclusionSelectors.find(domainStored);

					if (i == m_inclusionSelectors.end())
					{
						m_inclusionSelectors.insert({ domainStored, std::vector<SharedCategorizedCssSelector> {selector} });
					}
					else
					{
						i->second.push_back(selector);
					}					
				}

				void HttpFilteringEngine::AddExceptionSelector(boost::string_ref domain, const SharedCategorizedCssSelector& selector)
				{
					auto domainStored = util::string::Hash(boost::string_ref(domain));

					const auto& i = m_exceptionSelectors.find(domainStored);

					if (i == m_exceptionSelectors.end())
					{
						m_exceptionSelectors.insert({ domainStored, std::vector<SharedCategorizedCssSelector> {selector} });
					}
					else
					{
						i->second.push_back(selector);
					}
				}

				boost::string_ref HttpFilteringEngine::ExtractHostNameFromUrl(boost::string_ref url) const
				{
					size_t i = 0;
					bool m = true;

					auto sHttpSize = m_uriMethodHttp.size();
					auto sHttpsSize = m_uriMethodHttps.size();
					auto sSize = m_uriService.size();
					auto uSize = url.size();

					if (uSize <= sSize)
					{
						return url;
					}

					if (uSize > sHttpsSize)
					{
						auto subone = url.substr(0, sHttpSize);
						auto subtwo = url.substr(0, sHttpsSize);

						if (util::string::Equal(subone, m_uriMethodHttp))
						{							
							url = url.substr(sHttpSize);
						}
						else if(util::string::Equal(subone, m_uriMethodHttps))
						{							
							url = url.substr(sHttpsSize);
						}						
					}

					auto sub = url.substr(0, sSize);

					if (util::string::Equal(sub, m_uriService))
					{
						url = url.substr(sSize);
					}

					auto slashPos = url.find('/');
					if (slashPos != boost::string_ref::npos)
					{
						url = url.substr(slashPos);
					}

					return url;
				}

				std::string HttpFilteringEngine::ExtractHtmlText(const gq::Document* document) const
				{
					if (document != nullptr)
					{
						return document->GetText();
					}

					return std::string();
				}

				// const uint8_t category, const uint32_t payloadSizeBlocked, boost::string_ref fullRequest
				void HttpFilteringEngine::ReportRequestBlocked(const mhttp::HttpRequest* request, const mhttp::HttpResponse* response) const
				{
					if (m_onRequestBlocked)
					{						
						uint8_t blockedCategory = 0;
						uint32_t totalBytesBlocked = 0;

						std::string fullRequest;

						if (request != nullptr)
						{						

							blockedCategory = request->GetShouldBlock();

							fullRequest = request->RequestURI();
							const auto hostHeader = request->GetHeader(util::http::headers::Host);
							if (hostHeader.first != hostHeader.second)
							{
								fullRequest = hostHeader.first->second + fullRequest;
							}

							if (response != nullptr)
							{

								if (blockedCategory == 0)
								{
									blockedCategory = response->GetShouldBlock();
								}

								auto contentLenHeader = response->GetHeader(util::http::headers::ContentLength);

								if (contentLenHeader.first != contentLenHeader.second)
								{
									try
									{
										totalBytesBlocked = static_cast<uint32_t>(std::stoi(contentLenHeader.first->second));
									}
									catch (...)
									{
										// This isn't critical. We don't really care for the specifics of the exception. Maybe
										// it's a malicious web server, a broken one, or a troll putting "trololol" as the content
										// length. Who cares.

										ReportWarning(u8"In HttpFilteringEngine::ReportRequestBlocked(mhttp::HttpRequest*, mhttp::HttpResponse*) -  \
												Failed to parse content-length of blocked response. Using default average.");
									}
								}
							}
						}

						m_onRequestBlocked(blockedCategory, totalBytesBlocked, fullRequest.c_str(), fullRequest.size());
					}
				}

				void HttpFilteringEngine::ReportElementsBlocked(const uint32_t numElementsRemoved, boost::string_ref fullRequest) const
				{
					if (m_onElementsBlocked)
					{
						m_onElementsBlocked(numElementsRemoved, fullRequest.begin(), fullRequest.size());
					}
				}

				boost::string_ref HttpFilteringEngine::RemoveSchemeFromUri(boost::string_ref uri) const
				{
					boost::string_ref schemeEndStr(u8"://");
					auto schemeStart = uri.find(schemeEndStr);

					if (schemeStart != boost::string_ref::npos)
					{
						uri = uri.substr(schemeStart + schemeEndStr.size());
					}

					return uri;
				}

			} /* namespace http */
		} /* namespace filtering */
	} /* namespace httpengine */
} /* namespace te */