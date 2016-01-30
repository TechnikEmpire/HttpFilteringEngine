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

#include "HttpAbpInclusionFilter.hpp"
#include "HttpAbpExceptionFilter.hpp"

#include <gq/Document.hpp>
#include <gq/NodeMutationCollection.hpp>
#include <gq/Serializer.hpp>

namespace te
{
	namespace httpengine
	{
		namespace filtering
		{
			namespace http
			{

				const std::unordered_map<boost::string_ref, HttpAbpFilterOption, util::string::StringRefHash> HttpFilteringEngine::ValidFilterOptions
				{
					{ u8"script" , script },
					{ u8"~script" , notscript },
					{ u8"image" , image },
					{ u8"~image" , notimage },
					{ u8"stylesheet" , stylesheet },
					{ u8"~stylesheet" , notstylesheet },
					{ u8"object" , object },
					{ u8"~object" , notobject },
					{ u8"object_subrequest" , object_subrequest },
					{ u8"~object_subrequest" , notobject_subrequest },
					{ u8"subdocument" , subdocument },
					{ u8"~subdocument" , notsubdocument },
					{ u8"document" , document },
					{ u8"~document" , notdocument },
					{ u8"elemhide" , elemhide },
					{ u8"~elemhide" , notelemhide },
					{ u8"third_party" , third_party },
					{ u8"~third_party" , notthird_party },
					{ u8"xmlhttprequest" , xmlhttprequest },
					{ u8"~xmlhttprequest" , notxmlhttprequest }
				};
				
				HttpFilteringEngine::HttpFilteringEngine(
					const options::ProgramWideOptions* programOptions,
					util::cb::RequestBlockFunction onRequestBlocked,
					util::cb::ElementBlockFunction onElementsBlocked
					) :
					m_programOptions(programOptions),
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

				bool HttpFilteringEngine::LoadAbpFormattedListFromFile(
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
						return false;
					}

					std::string listContents;
					in.seekg(0, std::ios::end);

					auto fsize = in.tellg();

					if (fsize < 0 || static_cast<unsigned long long>(fsize) > static_cast<unsigned long long>(std::numeric_limits<size_t>::max()))
					{
						ReportError(u8"In HttpFilteringEngine::LoadAbpFormattedListFromFile(const std::string&, const uint8_t, const bool) - When loading file, ifstream::tellg() returned either less than zero or a number greater than this program can correctly handle.");
						return false;
					}

					listContents.resize(static_cast<size_t>(fsize));
					in.seekg(0, std::ios::beg);
					in.read(&listContents[0], listContents.size());
					in.close();

					return LoadAbpFormattedListFromString(listContents, listCategory, flushExistingRules);
				}

				bool HttpFilteringEngine::LoadAbpFormattedListFromString(
					const std::string& list, 
					const uint8_t listCategory, 
					const bool flushExistingRules
					)
				{
					Writer w(m_filterLock);

					if (flushExistingRules)
					{
						// If flushExistingRules is true, remove all existing filters from all containers that match the specified
						// category for the list.

						for (auto& rulePair : m_typelessIncludeRules)
						{
							rulePair.second.erase(std::remove_if(rulePair.second.begin(), rulePair.second.end(),
								[listCategory](const SharedFilter& s) -> bool
							{
								return s->GetCategory() == listCategory;
							}), rulePair.second.end());
						}

						for (auto& rulePair : m_typelessExcludeRules)
						{
							rulePair.second.erase(std::remove_if(rulePair.second.begin(), rulePair.second.end(),
								[listCategory](const SharedFilter& s) -> bool
							{
								return s->GetCategory() == listCategory;
							}), rulePair.second.end());
						}

						for (auto& rulePair : m_typedIncludeRules)
						{
							rulePair.second.erase(std::remove_if(rulePair.second.begin(), rulePair.second.end(),
								[listCategory](const SharedFilter& s) -> bool
							{
								return s->GetCategory() == listCategory;
							}), rulePair.second.end());
						}

						for (auto& rulePair : m_typedExcludeRules)
						{
							rulePair.second.erase(std::remove_if(rulePair.second.begin(), rulePair.second.end(),
								[listCategory](const SharedFilter& s) -> bool
							{
								return s->GetCategory() == listCategory;
							}), rulePair.second.end());
						}

						for (auto& selectorPair : m_inclusionSelectors)
						{
							selectorPair.second.erase(std::remove_if(selectorPair.second.begin(), selectorPair.second.end(),
								[listCategory](const SharedCategorizedCssSelector& s) -> bool
							{
								return s->GetCategory() == listCategory;
							}), selectorPair.second.end());
						}

						for (auto& selectorPair : m_exceptionSelectors)
						{
							selectorPair.second.erase(std::remove_if(selectorPair.second.begin(), selectorPair.second.end(),
								[listCategory](const SharedCategorizedCssSelector& s) -> bool
							{
								return s->GetCategory() == listCategory;
							}), selectorPair.second.end());
						}
					}

					bool noErrors = true;

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
							noErrors = false;
						}
					}

					return noErrors;
				}

				uint8_t HttpFilteringEngine::ShouldBlock(const mhttp::HttpRequest* request, const mhttp::HttpResponse* response)
				{
					#ifndef NEDEBUG
						assert(request != nullptr && u8"In HttpFilteringEngine::ShouldBlock(mhttp::HttpRequest*, mhttp::HttpResponse*) - The HttpRequest parameter was supplied with a nullptr. The request is absolutely required to do accurate HTTP filtering.");
					#else // !NEDEBUG
						if (request == nullptr)
						{
							throw std::runtime_error(u8"In HttpFilteringEngine::ShouldBlock(mhttp::HttpRequest*, mhttp::HttpResponse*) - The HttpRequest parameter was supplied with a nullptr. The request is absolutely required to do accurate HTTP filtering.");
						}
					#endif					
					
					// If the request is already set to be blocked, and the repsonse is supplied,
					// then we simply want to report the size of the blocked request based on the
					// response headers. We'll then return the existing ShouldBlock value from
					// the request's settings.
					if (response != nullptr && request->GetShouldBlock() != 0)
					{
						auto blockCategory = request->GetShouldBlock();

						auto contentLenHeader = response->GetHeader(util::http::headers::ContentLength);

						uint32_t blockedContentSize = AverageWebPageInBytes;

						if (contentLenHeader.first != contentLenHeader.second)
						{
							try
							{
								blockedContentSize = static_cast<uint32_t>(std::stoi(contentLenHeader.first->second));
							}
							catch (...)
							{
								// This isn't critical. We don't really care for the specifics of the exception. Maybe
								// it's a malicious web server, a broken on, or a troll putting "trololol" as the content
								// length. Who cares.

								ReportWarning(u8"In HttpFilteringEngine::ShouldBlock(mhttp::HttpRequest*, mhttp::HttpResponse*) -  \
												Failed to parse content-length of blocked response. Using default average.");
							}
						}

						auto fullRequest = request->RequestURI();
						const auto hostHeader = request->GetHeader(util::http::headers::Host);
						if (hostHeader.first != hostHeader.second)
						{
							fullRequest = hostHeader.first->second + u8"/" + fullRequest;
						}

						ReportRequestBlocked(blockCategory, blockedContentSize, fullRequest);

						return blockCategory;
					}

					HttpAbpFilterSettings transactionSettings;
					
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
						hostStringRef = boost::string_ref(hostHeaders.first->first);
					}

					hostStringRef = RemoveUriMethodAndService(hostStringRef);

					// Before going any further, we must verify that the extractedHost is not empty. If it is, then
					// we can't do a whole lot with this because the http request is fundamentally broken.
					if (hostStringRef.size() == 0)
					{
						ReportWarning(u8"In HttpFilteringEngine::HttpFilteringEngine::ShouldBlock(mhttp::HttpRequest*, mhttp::HttpResponse*) - Host declaration is missing from the HTTP request. As the request is fundamentally broken, aborting any further analysis.");
						return 0;
					}

					// First thing is to check and see if the request is third party or not. This can be easily
					// accomplished by comparing the referer string host against the destination host for the
					// request.
					auto refererHeaders = request->GetHeader(util::http::headers::Referer);

					boost::string_ref extractedRefererStrRef;

					if (refererHeaders.first != refererHeaders.second)
					{
						extractedRefererStrRef = boost::string_ref(refererHeaders.first->second);
					}

					extractedRefererStrRef = RemoveUriMethodAndService(extractedRefererStrRef);

					if (extractedRefererStrRef.size() == 0)
					{
						// If the referer is empty, it's almost 100% guaranteed that the request
						// is a direct navigation, meaning that the user manually requested this domain.
						// If that's the case, then the request definitely isn't third party.
						transactionSettings[HttpAbpFilterOption::notthird_party] = true;
					}
					else {
						if (extractedRefererStrRef.compare(extractedRefererStrRef) == 0)
						{
							transactionSettings[HttpAbpFilterOption::notthird_party] = true;
						}
						else {
							transactionSettings[HttpAbpFilterOption::third_party] = true;
						}
					}

					// Next, check if the request is an "XML Http Request" by checking the non-standard header
					// X-Requested-With. This is important because it's used rather heavily in ABP filters.
					auto requestedWithHeaders = request->GetHeader(util::http::headers::XRequestedWith);

					boost::string_ref xmlHttpRequestStrRef(u8"XMLHttpRequest");

					while (requestedWithHeaders.first != requestedWithHeaders.second)
					{						
						if (xmlHttpRequestStrRef.size() == requestedWithHeaders.first->second.size() && boost::iequals(requestedWithHeaders.first->second, xmlHttpRequestStrRef))
						{
							transactionSettings[HttpAbpFilterOption::xmlhttprequest] = true;
							break;
						}

						requestedWithHeaders.first++;
					}

					transactionSettings[HttpAbpFilterOption::notxmlhttprequest] = !transactionSettings[HttpAbpFilterOption::xmlhttprequest];

					// Until we know better, this request is not for any of the following types.
					// We're recycling the abp filter options to build a description of the
					// transaction here, rather than an abp formatted rule. So we're going to assume
					// explicitly, unless content-type tells us otherwise, that this transaction
					// isn't CSS, script or image content.
					transactionSettings[HttpAbpFilterOption::notscript] = true;
					transactionSettings[HttpAbpFilterOption::notimage] = true;
					transactionSettings[HttpAbpFilterOption::notstylesheet] = true;

					// This bool is basically used to indicate later that the response is present
					// and content-type data was extracted from it. If this is the case, then typed
					// rules will be checked. If not, then typed rules will be omitted.
					bool hasTypeData = false;

					if (response != nullptr)
					{
						if (response->IsPayloadImage())
						{
							transactionSettings[HttpAbpFilterOption::notimage] = false;
							transactionSettings[HttpAbpFilterOption::image] = true;
							hasTypeData = true;
						}
						else if (response->IsPayloadCss())
						{
							transactionSettings[HttpAbpFilterOption::notstylesheet] = false;
							transactionSettings[HttpAbpFilterOption::stylesheet] = true;
							hasTypeData = true;
						}
						else if (response->IsPayloadJavascript())
						{
							transactionSettings[HttpAbpFilterOption::notscript] = false;
							transactionSettings[HttpAbpFilterOption::script] = true;
							hasTypeData = true;
						}						
					}

					// boost::string_ref, I'd love you even more if you had ::append()
					std::string fullRequest = extractedRefererStrRef.to_string() + u8"/" + request->RequestURI();

					// All of the filtering objects internally use boost::string_ref for parsing and
					// storage, so they expect boost::string_ref objects for matching. Rather than
					// doing a bunch of allocations and copying when splitting filter strings up for
					// the matching routines, string_refs are used/
					boost::string_ref fullRequestStrRef(fullRequest);
					
					// Reader lock.
					Reader r(m_filterLock);

					// C++11 you've got to take by auto reference to avoid copying out the data
					// member of the pair. This can be observed by pushing unique_ptr wrapped
					// objects to a map and doing a find without an auto reference, as it won't even
					// compile for accessing the deleted copy ctor. This is a juicy little gotcha
					// that would have us copying potentially huge amounts of data, several times,
					// per http transaction, committing cold blooded homocide against performance,
					// so watch this.
					const auto& globalTypelessIncludesPair = m_typelessIncludeRules.find(m_globalRuleKey);
					const auto& domainTypelessIncludesPair = m_typelessIncludeRules.find(hostStringRef);

					const auto& globalTypelessExcludesPair = m_typelessExcludeRules.find(m_globalRuleKey);
					const auto& domainTypelessExcludesPair = m_typelessExcludeRules.find(hostStringRef);

					const size_t globalTypelessExcludeSize = (globalTypelessExcludesPair != m_typelessExcludeRules.end()) ? globalTypelessExcludesPair->second.size() : 0;
					const size_t globalTypelessIncludeSize = (globalTypelessIncludesPair != m_typelessIncludeRules.end()) ? globalTypelessIncludesPair->second.size() : 0;

					const size_t domainTypelessExcludeSize = (domainTypelessExcludesPair != m_typelessExcludeRules.end()) ? domainTypelessExcludesPair->second.size() : 0;
					const size_t domainTypelessIncludeSize = (domainTypelessIncludesPair != m_typelessIncludeRules.end()) ? domainTypelessIncludesPair->second.size() : 0;

					// We only want to check the typeless rules if the response is not present. The
					// idea here is that if a response is present, then the request should have
					// already been checked indepdently before reaching this phase. If a response is
					// present, that means that the initial request survived the global typeless
					// rules, so it's just a waste to recheck them again.
					if (response == nullptr)
					{
						// First thing we want to look for are exclusions. If we find an exclusion,
						// we can return without any further inspection. Check host specific rules
						// first, since that collection is bound to be much smaller.
						for (size_t he = 0; he < domainTypelessExcludeSize; ++he)
						{
							if ((m_programOptions->GetIsHttpCategoryFiltered(domainTypelessExcludesPair->second[he]->GetCategory())) &&
								domainTypelessExcludesPair->second[he]->IsMatch(fullRequestStrRef, transactionSettings, hostStringRef))
							{
								// Exclusion found, don't filter or block.
								return 0;
							}
						}

						for (size_t ge = 0; ge < globalTypelessExcludeSize; ++ge)
						{
							if ((m_programOptions->GetIsHttpCategoryFiltered(globalTypelessExcludesPair->second[ge]->GetCategory())) &&
								globalTypelessExcludesPair->second[ge]->IsMatch(fullRequestStrRef, transactionSettings, hostStringRef))
							{
								// Exclusion found, don't filter or block.
								return 0;
							}
						}
					}					

					// If hasTypeData is true, then we'll check the typed exclude rules as well.
					if (hasTypeData)
					{
						const auto& globalTypedExcludesPair = m_typedExcludeRules.find(m_globalRuleKey);
						const auto& domainTypedExcludesPair = m_typedExcludeRules.find(hostStringRef);

						const size_t globalTypedExcludeSize = (globalTypedExcludesPair != m_typedExcludeRules.end()) ? globalTypedExcludesPair->second.size() : 0;
						const size_t domainTypedExcludeSize = (domainTypedExcludesPair != m_typedExcludeRules.end()) ? domainTypedExcludesPair->second.size() : 0;

						// Check host specific rules first, since that collection is bound to be much smaller.
						for (size_t dte = 0; dte < domainTypedExcludeSize; ++dte)
						{
							if ((m_programOptions->GetIsHttpCategoryFiltered(domainTypedExcludesPair->second[dte]->GetCategory())) &&
								domainTypedExcludesPair->second[dte]->IsMatch(fullRequestStrRef, transactionSettings, hostStringRef))
							{
								// Exclusion found, don't filter or block.
								return 0;
							}
						}

						for (size_t gte = 0; gte < globalTypedExcludeSize; ++gte)
						{
							if ((m_programOptions->GetIsHttpCategoryFiltered(globalTypedExcludesPair->second[gte]->GetCategory())) &&
								globalTypedExcludesPair->second[gte]->IsMatch(fullRequestStrRef, transactionSettings, hostStringRef))
							{
								// Exclusion found, don't filter or block.
								return 0;
							}
						}
					}

					// We only want to check the typeless rules if the response is not present. The
					// idea here is that if a response is present, then the request should have
					// already been checked indepdently before reaching this phase. If a response is
					// present, that means that the initial request survived the global typeless
					// rules, so it's just a waste to recheck them again.
					if (response == nullptr)
					{
						// Beyond this point, inclusions are being looked for.
						for (size_t gi = 0; gi < globalTypelessIncludeSize; ++gi)
						{
							if ((m_programOptions->GetIsHttpCategoryFiltered(globalTypelessIncludesPair->second[gi]->GetCategory())) &&
								globalTypelessIncludesPair->second[gi]->IsMatch(fullRequestStrRef, transactionSettings, hostStringRef))
							{
								// Inclusion found, block and return the category of the matching rule.
								return globalTypelessIncludesPair->second[gi]->GetCategory();
							}
						}

						for (size_t di = 0; di < domainTypelessIncludeSize; ++di)
						{
							if ((m_programOptions->GetIsHttpCategoryFiltered(domainTypelessIncludesPair->second[di]->GetCategory())) &&
								domainTypelessIncludesPair->second[di]->IsMatch(fullRequestStrRef, transactionSettings, hostStringRef))
							{
								// Inclusion found, block and return the category of the matching rule.
								return domainTypelessIncludesPair->second[di]->GetCategory();
							}
						}
					}

					// If hasTypeData is true, then we'll check the typed include rules as well.
					if (hasTypeData)
					{
						const auto& globalTypedIncludesPair = m_typedIncludeRules.find(m_globalRuleKey);
						const auto& domainTypedIncludesPair = m_typedIncludeRules.find(hostStringRef);

						const size_t globalTypedIncludeSize = (globalTypedIncludesPair != m_typedIncludeRules.end()) ? globalTypedIncludesPair->second.size() : 0;
						const size_t domainTypedIncludeSize = (domainTypedIncludesPair != m_typedIncludeRules.end()) ? domainTypedIncludesPair->second.size() : 0;

						// Check host specific rules first, since that collection is bound to be much smaller.
						for (size_t dti = 0; dti < domainTypedIncludeSize; ++dti)
						{
							if ((m_programOptions->GetIsHttpCategoryFiltered(domainTypedIncludesPair->second[dti]->GetCategory())) &&
								domainTypedIncludesPair->second[dti]->IsMatch(fullRequestStrRef, transactionSettings, hostStringRef))
							{
								// Inclusion found, block and return the category of the matching rule.
								return domainTypedIncludesPair->second[dti]->GetCategory();
							}
						}

						for (size_t gti = 0; gti < globalTypedIncludeSize; ++gti)
						{
							if ((m_programOptions->GetIsHttpCategoryFiltered(globalTypedIncludesPair->second[gti]->GetCategory())) &&
								globalTypedIncludesPair->second[gti]->IsMatch(fullRequestStrRef, transactionSettings, hostStringRef))
							{
								// Inclusion found, block and return the category of the matching rule.
								return globalTypedIncludesPair->second[gti]->GetCategory();
							}
						}
					}

					// No matches of any kind were found, so the transaction should be allowed to complete.
					return 0;
				}				

				std::string HttpFilteringEngine::ProcessHtmlResponse(const mhttp::HttpRequest* request, const mhttp::HttpResponse* response) const
				{
					#ifndef NEDEBUG
						assert(request != nullptr && response != nullptr && u8"In HttpFilteringEngine::ProcessHtmlResponse(const mhttp::HttpRequest*, const mhttp::HttpResponse*) const - The HttpRequest or HttpResponse parameter was supplied with a nullptr. Both are absolutely required to be valid to accurately filter html payloads.");
					#else // !NEDEBUG
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
						// I would do anything to block, I'd run right in to hell and back. But I
						// won't do that.
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
						// XXX TODO - Why doesn't GQ take a string_ref param so we don't have to copy? Good grief,
						// who wrote that crap?
						doc->Parse(payloadString);
					}
					catch (std::runtime_error& e)
					{						
						// This would only happen, AFAIK, if we failed to parse any valid HTML.
						std::string errMessage(u8"In HttpFilteringEngine::ProcessHtmlResponse(const mhttp::HttpRequest*, const mhttp::HttpResponse*) const - Error:\n\t");
						errMessage.append(e.what());
						ReportError(errMessage);
						return std::string();
					}

					// Where we're going to collect all matched nodes.
					gq::NodeMutationCollection collection;		

					int numberOfHtmlElementsRemoved = 0;

					// We'll start out getting global selectors and running them against the
					// document, collecting all results into the NodeMutationCollection structure.
					const auto& globalIncludeSelectors = m_inclusionSelectors.find(m_globalRuleKey);

					if (globalIncludeSelectors != m_inclusionSelectors.end())
					{
						for (const auto& selector : globalIncludeSelectors->second)
						{
							if (m_programOptions->GetIsHttpCategoryFiltered(selector->GetCategory()))
							{
								doc->Each(selector->GetSelector(),
									[&collection, &numberOfHtmlElementsRemoved](const gq::Node* node)->void
								{
									// XXX TODO - This needs to be dropped after GQ is updated to give
									// NodeMutationCollection a ::Size() member, because this crude
									// counting method may count duplicates. GQ does not do duplicate
									// filtering before invoking these callbacks. Instead, since
									// NodeMutationCollection internally uses an unordered_set, it's
									// provided internally.
									++numberOfHtmlElementsRemoved;

									collection.Add(node);
								});
							}							
						}
					}

					// Try to get the host information from the request.
					boost::string_ref hostStringRef;

					auto hostHeaders = request->GetHeader(util::http::headers::Host);

					if (hostHeaders.first != hostHeaders.second)
					{
						hostStringRef = boost::string_ref(hostHeaders.first->first);
					}

					// If we got host information, we'll move to host specific selectors and collect
					// all results in the same collection.
					if (hostStringRef.size() > 0)
					{
						const auto& hostIncludeSelectors = m_inclusionSelectors.find(hostStringRef);

						if (hostIncludeSelectors != m_inclusionSelectors.end())
						{
							for (const auto& selector : hostIncludeSelectors->second)
							{
								if (m_programOptions->GetIsHttpCategoryFiltered(selector->GetCategory()))
								{
									doc->Each(selector->GetSelector(),
										[&collection, &numberOfHtmlElementsRemoved](const gq::Node* node)->void
									{
										// XXX TODO - This needs to be dropped after GQ is updated to give
										// NodeMutationCollection a ::Size() member, because this crude
										// counting method may count duplicates. GQ does not do duplicate
										// filtering before invoking these callbacks. Instead, since
										// NodeMutationCollection internally uses an unordered_set, it's
										// provided internally.
										++numberOfHtmlElementsRemoved;

										collection.Add(node);
									});
								}								
							}
						}

						// Now we have collected every possible element for removal, it's time to
						// prune down the collection with whitelist selectors. Start with host specific
						// while we're in this scope.

						const auto& hostExcludeSelectors = m_exceptionSelectors.find(hostStringRef);

						if (hostExcludeSelectors != m_exceptionSelectors.end())
						{
							for (const auto& selector : hostExcludeSelectors->second)
							{
								if (m_programOptions->GetIsHttpCategoryFiltered(selector->GetCategory()))
								{
									doc->Each(selector->GetSelector(),
										[&collection, &numberOfHtmlElementsRemoved](const gq::Node* node)->void
									{
										// XXX TODO - This needs to be dropped after GQ is updated to give
										// NodeMutationCollection a ::Size() member, because this crude
										// counting method may count duplicates. GQ does not do duplicate
										// filtering before invoking these callbacks. Instead, since
										// NodeMutationCollection internally uses an unordered_set, it's
										// provided internally.
										--numberOfHtmlElementsRemoved;

										collection.Remove(node);
									});
								}
							}
						}
					}

					// Now we'll run global whitelist selectors and prune our results further.
					const auto& globalExceptionSelectors = m_exceptionSelectors.find(m_globalRuleKey);

					if (globalExceptionSelectors != m_exceptionSelectors.end())
					{
						for (const auto& selector : globalExceptionSelectors->second)
						{
							if (m_programOptions->GetIsHttpCategoryFiltered(selector->GetCategory()))
							{

								doc->Each(selector->GetSelector(),
									[&collection, &numberOfHtmlElementsRemoved](const gq::Node* node)->void
								{
									// XXX TODO - This needs to be dropped after GQ is updated to give
									// NodeMutationCollection a ::Size() member, because this crude
									// counting method may count duplicates. GQ does not do duplicate
									// filtering before invoking these callbacks. Instead, since
									// NodeMutationCollection internally uses an unordered_set, it's
									// provided internally.
									--numberOfHtmlElementsRemoved;

									collection.Remove(node);
								});
							}
						}
					}

					// XXX TODO - Report numberOfHtmlElementsRemoved

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
						if (rule[1] == '@')
						{
							// Exception selector aka whitelist selector
							AddSelectorMultiDomain(m_globalRuleKey, rule.substr(2), category, true);
							return true;
						}
						else
						{
							// Inclusion selector aka blacklist selector
							AddSelectorMultiDomain(m_globalRuleKey, rule.substr(2), category);
							return true;
						}
					}
					else
					{
						// Note that this rule could still be a selector, but it would be bound to a specific domain. If
						// either of these strings are found, then it is a selection filter and the text preceeding these
						// matches is either a single domain or multiple domains separated by commas.
						auto selectorStartPosition = rule.find(u8"#");						
						
						if (selectorStartPosition != std::string::npos && (selectorStartPosition + 1 < rule.size()))
						{
							boost::string_ref domains = boost::string_ref(rule.c_str(), selectorStartPosition);

							// This is a selector rule with domain information attached.

							if (rule[selectorStartPosition + 1] == '@')
							{
								// Exception selector that is domain specific
								AddSelectorMultiDomain(m_globalRuleKey, rule.substr(2), category, true);
								return true;
							}
							else
							{
								// Inclusion selector that is domain specific
								AddSelectorMultiDomain(m_globalRuleKey, rule.substr(2), category);
								return true;
							}
						}
						else
						{
							// This is a filtering rule.

							// Check if there are attached options to the rule. These begin with "$".
							size_t ruleOptionsStart = rule.find_last_of(u8"$");

							std::string ruleOptions;
							std::string extractedRule;

							if (ruleOptionsStart != std::string::npos)
							{
								extractedRule = rule.substr(0, ruleOptionsStart);
								ruleOptions = rule.substr(ruleOptionsStart + 1);

								boost::trim(ruleOptions);
							}
							else
							{
								extractedRule = rule;
							}

							boost::trim(extractedRule);

							if (extractedRule.size() > 0)
							{
								if (extractedRule[0] == '/' && extractedRule[extractedRule.size() - 1] == '/')
								{
									// This is a regex rule. We don't want these. I believe there's only one regex
									// rule left inside of the ABP EasyList at the time of this writing.
									return false;
								}

								boost::string_ref ruleDomains;
								HttpAbpFilterSettings filterRuleOptions;
								std::vector<std::string> allRuleOptions;

								// Options are comma separated, so we attempt to split by commas.
								if (ruleOptions.find(",") != std::string::npos)
								{
									boost::split(allRuleOptions, ruleOptions, boost::is_any_of(","));
								}
								else
								{
									// If no commas, we'll just push the rule to the vector as to not
									// add unnecessary complexity.
									allRuleOptions.push_back(ruleOptions);
								}

								auto len = allRuleOptions.size();

								for (size_t i = 0; i < len; ++i)
								{
									boost::string_ref str(allRuleOptions[i]);
									boost::string_ref domainsOpt(u8"domain=");
									if (str.size() > domainsOpt.size() && str.substr(0, domainsOpt.size()).compare(domainsOpt) == 0)
									{
										str = str.substr(7);
										ruleDomains = str;
										continue;
									}
									else
									{
										const auto optionEnumResult = ValidFilterOptions.find(str);

										if (optionEnumResult == ValidFilterOptions.end())
										{
											// Invalid rule.
											std::string errMsg(u8"In HttpFilteringEngine::ProcessAbpFormattedRule(const std::string&, const uint8_t) - Invalid filtering rule option ");
											errMsg.append(str.to_string());
											ReportError(errMsg);
											continue;
										}

										// We have found a valid option, so we just set it to true.
										filterRuleOptions.set(optionEnumResult->second, true);
									}
								}

								bool isException = false;

								if (extractedRule.size() >= 2 && extractedRule[0] == '@' && extractedRule[1] == '@')
								{
									//Exception filter
									isException = true;
									extractedRule.erase(0, 2);
								}

								if (isException)
								{
									AddExceptionFilterMultiDomain(ruleDomains, extractedRule, filterRuleOptions, category);
								}
								else
								{
									AddInclusionFilterMultiDomain(ruleDomains, extractedRule, filterRuleOptions, category);
								}
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
						std::string errMsg(u8"In HttpFilteringEngine::AddIncludeSelectorMultiDomain(boost::string_ref, const std::string&, const uint8_t) Error:\n\t");
						errMsg.append(e.what());
						ReportError(errMsg);
						return;
					}					

					#ifndef NEDEBUG
						assert(sSelector != nullptr && u8"In HttpFilteringEngine::AddIncludeSelectorMultiDomain(boost::string_ref, const std::string&, const uint8_t) - Failed to allocate shared selector.");
					#else // !NEDEBUG
						if (sSelector == nullptr)
						{
							throw std::runtime_error(u8"In HttpFilteringEngine::AddIncludeSelectorMultiDomain(boost::string_ref, const std::string&, const uint8_t) - Failed to allocate shared selector.");
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
					// This absolutely must be done, otherwise we can't guarantee that the string which
					// the "domain" argument wraps will survive the lifetime of this object, which may
					// destroy the universe.
					auto domainStored = GetPreservedDomainStringRef(domain);

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
					// This absolutely must be done, otherwise we can't guarantee that the string which
					// the "domain" argument wraps will survive the lifetime of this object, which may
					// destroy the universe.
					auto domainStored = GetPreservedDomainStringRef(domain);

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

				void HttpFilteringEngine::AddInclusionFilterMultiDomain(
					boost::string_ref domains, 
					const std::string& rule, 
					HttpAbpFilterSettings options, 
					const uint8_t category
					)
				{

					// Note the key difference between handling exceptions in Inclusion filters and
					// Exception filters. In Inclusion filters, exceptions can simply be copied to
					// the Exclusion filters storage lists, because exceptions are always checked
					// first when running filters.
					// 
					// However, with exceptions, because of this ordering, we cannot do this. We
					// need have the Exception filter class(es) absord their exception information
					// and put it to use in their ::IsMatch override so that they can correctly
					// detect their own exceptions and return "false" if/when one is found.
					// 
					// We see a lot of code duplication between AddInclusionFilterMultiDomain and
					// AddExceptionFilterMultiDomain, but I've kept them as separate methods because
					// I believe the tradeoff is very messy and over-complicated logic when trying
					// to merge both methods into a single method with a "const bool isException" 
					// parameter.

					SharedInclusionFilter filter = nullptr;

					try
					{
						filter = std::make_shared<HttpAbpInclusionFilter>(rule, options, category);
					}
					catch (std::runtime_error& e)
					{
						std::string errMsg(u8"In HttpFilteringEngine::AddInclusionFilterMultiDomain(boost::string_ref, const std::string&, const HttpAbpFilterSettings, const uint8_t) Error:\n\t");
						errMsg.append(e.what());
						ReportError(errMsg);
						return;
					}

					#ifndef NEDEBUG
						assert(filter != nullptr && u8"In HttpFilteringEngine::AddInclusionFilterMultiDomain(boost::string_ref, const std::string&, const HttpAbpFilterSettings, const uint8_t) - Failed to allocate shared filter.");
					#else // !NEDEBUG
						if (sSelector == nullptr)
						{
							throw std::runtime_error(u8"In HttpFilteringEngine::AddInclusionFilterMultiDomain(boost::string_ref, const std::string&, const HttpAbpFilterSettings, const uint8_t) - Failed to allocate shared filter.");
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
						// Single domain supplied. We need to check if the single domain specified
						// in the rule is an exception domain. If it is, we'll push a copy of this
						// shared rule to the exception filter storage for just that domain, then
						// push a copy of this shared rule to the inclusion filter storage with the
						// wildcard aka any domain key.
						if (domains.size() > 1)
						{
							if (domains[0] == '~')
							{
								domains = domains.substr(1);
								AddExceptionFilter(domains, filter);
								AddInclusionFilter(m_globalRuleKey, filter);
							}
							else
							{
								AddInclusionFilter(domains, filter);
							}							
						}
						else
						{
							// XXX TODO report error.
						}						
					}
					else
					{
						// Multi domain
						auto domainsVector = util::string::Split(domains, delim);

						// If there wasn't a single inclusion domain (without '~' preceeding it),
						// then we need to add the rule as a global inclusion.
						bool hadOneNonExceptionDomain = false;

						for (auto domain : domainsVector)
						{
							if (domain.size() > 1)
							{
								if (domain[0] == '~')
								{
									domain = domain.substr(1);

									// Since this is an exception to an inclusion filter, we'll just
									// push a copy of this shared rule to the exceptions storage for
									// this domain alone.

									AddExceptionFilter(domain, filter);
								}
								else
								{
									hadOneNonExceptionDomain = true;
									AddInclusionFilter(domain, filter);
								}
							}
							else
							{
								// XXX TODO report error
							}
						}

						if (!hadOneNonExceptionDomain)
						{
							AddInclusionFilter(m_globalRuleKey, filter);
						}
					}
				}

				void HttpFilteringEngine::AddExceptionFilterMultiDomain(
					boost::string_ref domains, 
					const std::string& rule, 
					HttpAbpFilterSettings options, 
					const uint8_t category
					)
				{
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

					std::vector<std::string> exceptionDomains;
					std::vector<boost::string_ref> inclusionDomains;

					if (delim == 0)
					{
						// Single domain supplied. We need to check if the single domain specified
						// in the rule is an exception domain. If it is, we'll push a copy of this
						// shared rule to the exception filter storage for just that domain, then
						// push a copy of this shared rule to the inclusion filter storage with the
						// wildcard aka any domain key.
						if (domains.size() > 1)
						{
							if (domains[0] == '~')
							{
								domains = domains.substr(1);
								exceptionDomains.push_back(domains.to_string());
							}
							else
							{
								inclusionDomains.push_back(domains);
							}
						}
						else
						{
							// XXX TODO report error.
						}
					}
					else
					{
						// Multi domain
						auto domainsVector = util::string::Split(domains, delim);

						// If there wasn't a single inclusion domain (without '~' preceeding it),
						// then we need to add the rule as a global exception.
						bool hadOneNonExceptionDomain = false;

						for (auto domain : domainsVector)
						{
							if (domain.size() > 1)
							{
								if (domain[0] == '~')
								{
									domain = domain.substr(1);
									
									exceptionDomains.push_back(domains.to_string());
								}
								else
								{
									hadOneNonExceptionDomain = true;
									inclusionDomains.push_back(domains);
								}
							}
							else
							{
								// XXX TODO report error
							}
						}

						if (!hadOneNonExceptionDomain)
						{
							inclusionDomains.push_back(m_globalRuleKey);
						}
					}

					SharedExceptionFilter filter = nullptr;

					try
					{
						filter = std::make_shared<HttpAbpExceptionFilter>(rule, options, exceptionDomains, category);
					}
					catch (std::runtime_error& e)
					{
						std::string errMsg(u8"In HttpFilteringEngine::AddExceptionFilterMultiDomain(boost::string_ref, const std::string&, const HttpAbpFilterSettings, const uint8_t) Error:\n\t");
						errMsg.append(e.what());
						ReportError(errMsg);
						return;
					}

					#ifndef NEDEBUG
						assert(filter != nullptr && u8"In HttpFilteringEngine::AddExceptionFilterMultiDomain(boost::string_ref, const std::string&, const HttpAbpFilterSettings, const uint8_t) - Failed to allocate shared filter.");
					#else // !NEDEBUG
					if (sSelector == nullptr)
						{
							throw std::runtime_error(u8"In HttpFilteringEngine::AddExceptionFilterMultiDomain(boost::string_ref, const std::string&, const HttpAbpFilterSettings, const uint8_t) - Failed to allocate shared filter.");
						}
					#endif	

					for (auto domainStrRef : inclusionDomains)
					{
						AddExceptionFilter(domainStrRef, filter);
					}
				}

				void HttpFilteringEngine::AddInclusionFilter(boost::string_ref domain, const SharedFilter& filter)
				{
					// Nullchecks and asserts are already done on filter before reaching here, as this method
					// is only ever called by the AddXFilterMultiDomain(...). If that ever changes, then
					// XXX TODO add asserts and release checks here.

					// This absolutely must be done, otherwise we can't guarantee that the string which
					// the "domain" argument wraps will survive the lifetime of this object, which may
					// destroy the universe.
					auto domainStored = GetPreservedDomainStringRef(domain);
					
					std::unordered_map<boost::string_ref, std::vector<SharedFilter>, util::string::StringRefHash>* container = nullptr;

					if (filter->IsTypeBound())
					{
						container = &m_typedIncludeRules;
					}
					else
					{
						container = &m_typelessIncludeRules;
					}

					const auto& i = container->find(domainStored);

					if (i == container->end())
					{
						container->insert({ domainStored, std::vector<SharedFilter> {filter} });
					}
					else
					{
						i->second.push_back(filter);
					}
				}

				void HttpFilteringEngine::AddExceptionFilter(boost::string_ref domain, const SharedFilter& filter)
				{
					// Nullchecks and asserts are already done on filter before reaching here, as this method
					// is only ever called by the AddXFilterMultiDomain(...). If that ever changes, then
					// XXX TODO add asserts and release checks here.

					// This absolutely must be done, otherwise we can't guarantee that the string which
					// the "domain" argument wraps will survive the lifetime of this object, which may
					// destroy the universe.
					auto domainStored = GetPreservedDomainStringRef(domain);

					std::unordered_map<boost::string_ref, std::vector<SharedFilter>, util::string::StringRefHash>* container = nullptr;

					if (filter->IsTypeBound())
					{
						container = &m_typedExcludeRules;
					}
					else
					{
						container = &m_typelessExcludeRules;
					}

					const auto& i = container->find(domainStored);

					if (i == container->end())
					{
						container->insert({ domainStored, std::vector<SharedFilter> {filter} });
					}
					else
					{
						i->second.push_back(filter);
					}
				}

				boost::string_ref HttpFilteringEngine::RemoveUriMethodAndService(boost::string_ref url) const
				{
					// This is much, much faster than using built-in methods like ::compare().

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

				boost::string_ref HttpFilteringEngine::GetPreservedDomainStringRef(boost::string_ref domain)
				{
					// Special case of the global key. Already stored safely in static storage
					// wrapped by member variable.
					if (domain.size() == 0  || (domain.size() == 1 && domain[0] == '*'))
					{
						return m_globalRuleKey;
					}

					// So when all things are considered, this seems like it's a lot of extra work
					// for little benefit. Yes, we generate a bunch of copies by calling to_string,
					// but this is done once at program startup, maybe twice max if list updates are available.
					// 
					// Because we have several containers that store domain information, we end up
					// saving in the long run, and get to avoid making copies continnuously on every
					// single HTTP transaction of host strings and such.
					std::string domainString = domain.to_string();

					// Simply do an insert. If the item exists, we'll get back the inserted/stored
					// string. If the value doesn't exist, an insert will happen and we'll still get
					// back the inserted/stored string. It's this we want to wrap in-place and return.
					const auto& insertResult = m_allKnownListDomains.insert(domainString);

					boost::string_ref domainFromStorage(insertResult.first->c_str());

					return domainFromStorage;
				}

				void HttpFilteringEngine::ReportRequestBlocked(const uint8_t category, const uint32_t payloadSizeBlocked, boost::string_ref fullRequest) const
				{
					if (m_onRequestBlocked)
					{
						m_onRequestBlocked(category, payloadSizeBlocked, fullRequest.begin(), fullRequest.size());
					}
				}

				void HttpFilteringEngine::ReportElementsBlocked(const uint32_t numElementsRemoved, boost::string_ref fullRequest) const
				{
					if (m_onElementsBlocked)
					{
						m_onElementsBlocked(numElementsRemoved, fullRequest.begin(), fullRequest.size());
					}
				}

			} /* namespace http */
		} /* namespace filtering */
	} /* namespace httpengine */
} /* namespace te */