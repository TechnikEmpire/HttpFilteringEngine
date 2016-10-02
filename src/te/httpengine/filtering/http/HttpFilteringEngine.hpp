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
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <boost/predef/os.h>
#include <boost/algorithm/string.hpp>
#include <boost/thread/lock_types.hpp>
#include <boost/thread/shared_mutex.hpp>
#include "../../../util/string/StringRefUtil.hpp"
#include "../../util/cb/EventReporter.hpp"
#include "AbpFilterOptions.hpp"

/// <summary>
/// Forward decl for gq structures.
/// </summary>
namespace gq
{
	class Document;
}

/// <summary>
/// Forward decl for mitm structures.
/// </summary>
namespace te
{
	namespace httpengine
	{
		namespace mitm
		{
			namespace http
			{
				class HttpRequest;
				class HttpResponse;
			}
		}

		namespace filtering
		{
			namespace options
			{
				class ProgramWideOptions;
			}
		}
	}
}

namespace te
{
	namespace httpengine
	{
		namespace filtering
		{
			namespace http
			{						

				/// <summary>
				/// Forward decl selector/filter structures.
				/// </summary>
				class AbpFilter;
				class AbpFilterParser;
				class CategorizedCssSelector;

				namespace 
				{
					namespace mhttp = te::httpengine::mitm::http;
				}

				/// <summary>
				/// The HttpFilteringEngine is meant to provide a simple interface where Http
				/// requests and responses can be evaluated together or independently to determine
				/// if the transactions should be blocked or not, based on current option settings
				/// and supplied filters.
				/// </summary>
				class HttpFilteringEngine : public util::cb::EventReporter
				{

				private:
										
					using Reader = boost::shared_lock<boost::shared_mutex>;
					using Writer = boost::unique_lock<boost::shared_mutex>;

					using SharedCategorizedCssSelector = std::shared_ptr<CategorizedCssSelector>;

				public:

					/// <summary>
					/// Constructs a HttpFilteringEngine object with the supplied ProgramWideOptions
					/// pointer. These options are required and are designed to have a program-long
					/// lifetime, but must at the very least match the lifetime of this object.
					/// </summary>
					/// <param name="programOptions">
					/// A valid pointer to a ProgramWideOptions object which must have a lifetime at
					/// least equal to the lifetime of this object.
					/// </param>
					/// <param name="onInfo">
					/// Optional callback where informational messages about internal function can be
					/// sent. Defaults to nullptr.
					/// </param>
					/// <param name="onWarn">
					/// Optional callback where warning messages about internal function can be sent.
					/// Defaults to nullptr.
					/// </param>
					/// <param name="onError">
					/// Optional callback where error messages about internal function can be sent.
					/// Defaults to nullptr.
					/// </param>
					/// <param name="onClassify">
					/// A function where the contents of a payload, along with the declared content
					/// type can be sent for classification. Defaults to nullptr.
					/// </param>
					/// <param name="onRequestBlocked">
					/// Callback where information about blocked requests can be sent.
					/// </param>
					/// <param name="onElementsBlocked">
					/// Callback where information about element hiding/removal can be sent.
					/// </param>
					HttpFilteringEngine(
						const options::ProgramWideOptions* programOptions,
						util::cb::MessageFunction onInfo = nullptr,
						util::cb::MessageFunction onWarn = nullptr,
						util::cb::MessageFunction onError = nullptr,
						util::cb::ContentClassificationFunction onClassify = nullptr,
						util::cb::RequestBlockFunction onRequestBlocked = nullptr,
						util::cb::ElementBlockFunction onElementsBlocked = nullptr
						);				

					/// <summary>
					/// No copy no move nothx.
					/// </summary>
					HttpFilteringEngine(const HttpFilteringEngine&) = delete;
					HttpFilteringEngine(HttpFilteringEngine&&) = delete;
					HttpFilteringEngine& operator=(const HttpFilteringEngine&) = delete;
					
					/// <summary>
					/// Default destructor.
					/// </summary>
					~HttpFilteringEngine();

					/// <summary>
					/// Load and parse a list of selectors and filters, written in Adblock Plus
					/// Filter syntax. Ensure that you specify the absolute path to the resource on
					/// disk and ensure that read permissions are set appropriately.
					///
					/// Note that mutex based synchronization occurs when calling this method, and
					/// that collections of lists can be quite long, so this can be an expensive
					/// blocking operation. The need for synchronization is because these filters are
					/// both simultaneously available for reading to multiple concurrent readers,
					/// while also available for flushing and reloading or appending without
					/// requiring a restart, say from the UI thread.
					///
					/// Note that this function is designed to return true if there were no errors
					/// detected while processing the rules, false otherwise. We strike a balance
					/// here between properly handling issues and allowing the program to continue
					/// when non critical errors occur. The type of error in mind here is when a rule
					/// that is not formatted correctly is encountered and cannot be processed. We
					/// want to alert the user that something did happen that should be investigated,
					/// but we don't want to explode the program because one or two rules out of
					/// thousands was broken.
					///
					/// Even in the event that the supplied file is not found or is unreadable, this
					/// function will not throw, but rather through the inherited EventReporter
					/// interface will provide specific information about the issues encountered.
					/// This library is meant to be integrated into a products for general users
					/// where it will encounter a myriad of unpredictable input both from the user
					/// and from network traffic. Crashing because a user failed to properly point to
					/// a file is not acceptable. As such, throws are reserved for extraordinary
					/// circumstances and asserts are used to control proper usage.
					/// </summary>
					/// <param name="listFilePath">
					/// The absolute path to a list of selectors and filters, written in Adblock Plus
					/// Filter syntax.
					/// </param>
					/// <param name="listCategory">
					/// The category that the parsed selectors and filters are deemed to belong to.
					/// This is required for allowing enabling and disabling of filtering categories
					/// at will.
					/// </param>
					/// <param name="flushExistingRules">
					/// If set to true, all existing rules for the specified category will be erased
					/// from the collection before the newly loaded and parsed entries are stores.
					/// </param>
					/// <returns>
					/// A pair containing a count of the rules successfully loaded on the left hand
					/// side, and a count of the rules that failed to load on the right hand side.
					/// Via the EventReporter interface, meaningful information about any the issue
					/// (in the event of a count of failed rules greater than zero) should be
					/// generated, so ensure that interacting objects are subscribed to those events.
					/// </returns>
					std::pair<uint32_t, uint32_t> LoadAbpFormattedListFromFile(const std::string& listFilePath, const uint8_t listCategory, const bool flushExistingRules);

					/// <summary>
					/// Parse a list of selectors and filters, written in Adblock Plus Filter
					/// syntax, from the supplied std::string object.
					/// 
					/// Note that mutex based synchronization occurs when calling this method, and
					/// that collections of lists can be quite long, so this can be an expensive
					/// blocking operation. The need for synchronization is because these filters
					/// are both simultaneously available for reading to multiple concurrent
					/// readers, while also available for flushing and reloading or appending
					/// without requiring a restart, say from the UI thread.
					/// 
					/// Note that this function is designed to return true if there were no errors
					/// detected while processing the rules, false otherwise. We strike a balance
					/// here between properly handling issues and allowing the program to continue
					/// when non critical errors occur. The type of error in mind here is when a
					/// rule that is not formatted correctly is encountered and cannot be processed.
					/// We want to alert the user that something did happen that should be
					/// investigated, but we don't want to explode the program because one or two
					/// rules out of thousands was broken.
					/// </summary>
					/// <param name="list">
					/// A list of selectors and filters, written in Adblock Plus Filter syntax,
					/// separated by newline \ n.
					/// </param>
					/// <param name="listCategory">
					/// The category that the parsed selectors and filters are deemed to belong to.
					/// This is required for allowing enabling and disabling of filtering categories
					/// at will.
					/// </param>
					/// <param name="flushExistingRules">
					/// If set to true, all existing rules for the specified category will be erased
					/// from the collection before the newly loaded and parsed entries are stores.
					/// </param>
					/// <returns>
					/// A pair containing a count of the rules successfully loaded on the left hand
					/// side, and a count of the rules that failed to load on the right hand side.
					/// Via the EventReporter interface, meaningful information about any the issue
					/// (in the event of a count of failed rules greater than zero) should be
					/// generated, so ensure that interacting objects are subscribed to those events.
					/// </returns>
					std::pair<uint32_t, uint32_t> LoadAbpFormattedListFromString(const std::string& list, const uint8_t listCategory, const bool flushExistingRules);

					/// <summary>
					/// Loads text keywords from a file. Each unique keyword must be on a newline
					/// within the file. Note that text triggers should be used sparingly. You should
					/// only really use entries highly specific to content that you really don't want
					/// to get through, such as pornography. Any payload that is text based will be
					/// subjected to filtering via these triggers, so beware. You want want
					/// non-specific/common text as a trigger.
					/// </summary>
					/// <param name="triggers">
					/// The string holding the newline-delimited list of trigger words.
					/// </param>
					/// <param name="category">
					/// The category that extracted triggers belong to.
					/// </param>
					/// <param name="flushExisting">
					/// Whether or not to flush existing triggers before loading the new ones.
					/// </param>
					/// <returns>
					/// The total number of triggers loaded from the provided source.
					/// </returns>
					uint32_t LoadTextTriggersFromFile(const std::string& triggersFilePath, const uint8_t category, const bool flushExisting);

					/// <summary>
					/// Loads text keywords from a string. Each unique keyword must be on a newline.
					/// Note that text triggers should be used sparingly. You should only really use
					/// entries highly specific to content that you really don't want to get through,
					/// such as pornography. Any payload that is text based will be subjected to
					/// filtering via these triggers, so beware. You want want non-specific/common
					/// text as a trigger.
					/// </summary>
					/// <param name="triggers">
					/// The string holding the newline-delimited list of trigger words.
					/// </param>
					/// <param name="category">
					/// The category that extracted triggers belong to.
					/// </param>
					/// <param name="flushExisting">
					/// Whether or not to flush existing triggers before loading the new ones.
					/// </param>
					/// <returns>
					/// The total number of triggers loaded from the provided source.
					/// </returns>
					uint32_t LoadTextTriggersFromString(const std::string& triggers, const uint8_t category, const bool flushExisting);

					/// <summary>
					/// Unloads any and all filtering rules assigned to the given category.
					/// </summary>
					/// <param name="category">
					/// The category for which to unload all rules.
					/// </param>
					void UnloadAllFilterRulesForCategory(const uint8_t category);

					/// <summary>
					/// Unloads any and all text triggers for the given category.
					/// </summary>
					/// <param name="category">
					/// The category for which to unload all text triggers.
					/// </param>
					void UnloadAllTextTriggersForCategory(const uint8_t category);

					/// <summary>
					/// Determine if a transaction should be blocked from completing. If the
					/// HttpResponse is supplied, full return payload composition will be analyzed,
					/// meaning that filters which specify that they are exclusively bound to
					/// responses generating a particular type of content (CSS, Image, etc) will be
					/// considered. If the request alone is supplied, these filters will not be
					/// considered, since it is impossible to accurately determine such things
					/// without having at least the response headers.
					/// </summary>
					/// <param name="request">
					/// Pointer to the request side of the HTTP transaction to consider for blocking.
					/// Absolutely must be a valid pointer.
					/// </param>
					/// <param name="response">
					/// Pointer to the response side of the HTTP transaction to consider for
					/// blocking. Optional, defaulting to nullptr. Note the parameter is non-const.
					/// Responses will be modified if necessary for further inspection.
					/// </param>
					/// <param name="isSecure">
					/// Indicates whether or not the transaction is HTTP or HTTPS. Required to
					/// accurately rebuild the full request string for proper filter matching.
					/// </param>
					/// <returns>
					/// Anything other than ContentFilteringCategory::None if it has been determined
					/// that the transaction should be blocked. The return value represents the
					/// filtering category that the the transaction was found to belong to. A
					/// ContentFilteringCategory::None return indicates that no matching filter could
					/// be found, or that the category for a matched filter was disabled, and thus
					/// the request should not be blocked.
					/// </returns>
					uint8_t ShouldBlock(const mhttp::HttpRequest* request, mhttp::HttpResponse* response = nullptr, const bool isSecure = false);					

					/// <summary>
					/// Attempts to load and parse the response portion of the supplied transaction,
					/// then runs all relevant CSS selectors against the document, collecting nodes
					/// that match the supplied selectors. Once this is done, the document is
					/// serialized back to an HTML string and, during this serialization process,
					/// all matched nodes are removed. This functionality is entirely provided by
					/// the third-party library GQ.
					/// 
					/// Note that if the payload on the response side in fact not valid or supported
					/// HTML data, this function will return an empty string. This function does not
					/// modify any input at all, but rather attempts to return a result that the
					/// user can use in a fashion that the engine is agnostic of. However, common
					/// practice and intended purpose are to simply replace the response payload
					/// with the data returned from this method.
					/// </summary>
					/// <param name="request">
					/// The request side of the transaction. Must not be nullptr.
					/// </param>
					/// <param name="response">
					/// The response side of the transaction. Must not be nullptr.
					/// </param>
					/// <returns>
					/// If valid, supported HTML was found in the response payload and it was
					/// successfully parsed, a string containing the filtered HTML. Otherwise, an
					/// empty string.
					/// </returns>
					std::string ProcessHtmlResponse(const mhttp::HttpRequest* request, const mhttp::HttpResponse* response);

				private:

					using SharedFilter = std::shared_ptr<AbpFilter>;

					/// <summary>
					/// Pointer to the provided ProgramWideOptions object governing the functionality
					/// of this filtering engine.
					/// </summary>
					const options::ProgramWideOptions* m_programOptions;

					/// <summary>
					/// Whenever a request or response with a full payload is submitted to determine
					/// if it should be blocked or not, if this function is available, it will be
					/// called to classify the payload content.
					/// </summary>
					util::cb::ContentClassificationFunction m_onClassifyContent = nullptr;

					/// <summary>
					/// Whenever a request is blocked, the filtering engine will attempt to generate
					/// information about the request, such as the total size of the request, which
					/// it can report to an observer through this callback, if the callback was
					/// supplied during construction.
					/// </summary>
					util::cb::RequestBlockFunction m_onRequestBlocked = nullptr;

					/// <summary>
					/// Whenever elements are removed from an HTML response payload, the filtering
					/// engine will attempt to generate information about that event, such as the
					/// total number of elements removed, which it can report to an observer through
					/// this callback, if the callback was supplied during construction.
					/// </summary>
					util::cb::ElementBlockFunction m_onElementsBlocked = nullptr;

					/// <summary>
					/// Filtering rule parser.
					/// </summary>
					std::unique_ptr<AbpFilterParser> m_filterParser;

					/// <summary>
					/// Currently, this program buries its head in the sand and pretends that
					/// International Domain Names don't exist, the tell tale sign of an unrepentant
					/// anglophile. In the future, this needs to be addressed, so this is marked
					/// with a XXX TODO . This string is used in a hackish method that pilfers
					/// through text data, agnostic of format, brute-force extracting anything that
					/// resembles a domain and checking to see if its a pornographic link.
					/// </summary>
					const boost::string_ref m_validDomainCharacters = u8"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890.-_";

					/// <summary>
					/// Used for removing superflous parts of request information before storing and
					/// comparing.
					/// </summary>
					const boost::string_ref m_uriMethodHttp = u8"http://";

					/// <summary>
					/// Used for removing superflous parts of request information before storing and
					/// comparing.
					/// </summary>
					const boost::string_ref m_uriMethodHttps = u8"https://";

					/// <summary>
					/// Used for removing superflous parts of request information before storing and
					/// comparing.
					/// </summary>
					const boost::string_ref m_uriService = u8"www.";

					/// <summary>
					/// All of the storage hashmaps for rules use an asterik for global rules,
					/// meaning rules that are not bound to any specific domain. Deemed simpler and
					/// cheaper to store this here as a const string rather than doing unnecessary
					/// allocations in check methods.
					/// </summary>
					const boost::string_ref m_globalRuleKey = u8"*";					

					/// <summary>
					/// Shared mutex used for handling single writer, multiple reader scenario where
					/// filters stored in containers are simultaneously used by N readers, but the
					/// container may be modified (emptied, appended to) during, and exclusive locks
					/// are required for proper synchronization.
					/// </summary>
					boost::shared_mutex m_filterLock;

					/// <summary>
					/// All hashmaps in this object, except this one, use string_ref as their keys.
					/// There are several benefits to this. First, a great many Adblock Plus
					/// formatted filters have some form of domain information associated with them.
					/// Even those that do not, they are filtered against HTTP transactions where
					/// the domain is known and, without using a string_ref key, every filtering
					/// attempt would incur unnecessary copies. This way, we can provide fast,
					/// copy-free lookups and comparisons for every single filter (with only one
					/// exception, building out the entire request string. No ::append() method in
					/// boost::string_ref unfortunately).
					/// 
					/// Also, we can do very fast inspection of transaction payloads, searching for
					/// links which can aid greatly in establishing classification by association,
					/// all without doing a single string copy.
					/// 
					/// However, boost::string_ref (and any good string_ref obviously) holds no
					/// ownership of the underlying data. So, any time a domain is encountered in
					/// parsing rule lists, it will be stored here, if not already, providing a
					/// string_ref view of its internal data. This will guarantee the lifetimes of the
					/// string_ref hashtable keys to be equal to their containing parents.
					/// </summary>
					std::unordered_set<std::string> m_allKnownListDomains;

					/// <summary>
					/// Used for storing inclusion filters that do not specify any constraints in
					/// their options that cannot be immediately known upon first receiving a
					/// request. This means that filters that specify no options or only options
					/// such as third-party or not-third-party, or xmlhttprequest etc are held in
					/// this container. This is an optimization, to not waste time checking things
					/// that cannot possibly be accurately matched, while hoping to find a match or
					/// exclusion match immediately to prevent any further rule processing against
					/// the request.
					/// 
					/// This container holds both host-specific and global (no domain specified)
					/// filters. All global filters use the key "*", while all other host-bound
					/// rules use the host domain name, with no protocol or service applied
					/// (http://, https://, www.) as the key.
					/// </summary>
					std::unordered_map<boost::string_ref, std::vector<SharedFilter>, util::string::StringRefICaseHash, util::string::StringRefIEquals> m_typelessIncludeRules;

					/// <summary>
					/// Used for storing exclusion filters that do not specify any constraints in
					/// their options that cannot be immediately known upon first receiving a
					/// request. This means that filters that specify no options or only options
					/// such as third-party or not-third-party, or xmlhttprequest etc are held in
					/// this container. This is an optimization, to not waste time checking things
					/// that cannot possibly be accurately matched, while hoping to find a match or
					/// exclusion match immediately to prevent any further rule processing against
					/// the request.
					/// 
					/// This container holds both host-specific and global (no domain specified)
					/// filters. All global filters use the key "*", while all other host-bound
					/// rules use the host domain name, with no protocol or service applied
					/// (http://, https://, www.) as the key.
					/// </summary>
					std::unordered_map<boost::string_ref, std::vector<SharedFilter>, util::string::StringRefICaseHash, util::string::StringRefIEquals> m_typelessExcludeRules;

					/// <summary>
					/// Used for storing inclusion filters which contain settings that bind the filters
					/// in this container to only match specific content types, among other things. Such
					/// rules cannot possibly be matched reliably when checking the request portion
					/// of a transaction only, so the rules are separated as to not be accessed when
					/// only a request is supplied to any ::ShouldBlock* methods.
					/// 
					/// This container holds both host-specific and global (no domain specified)
					/// filters. All global filters use the key "*", while all other host-bound
					/// rules use the host domain name, with no protocol or service applied
					/// (http://, https://, www.) as the key.
					/// </summary>
					std::unordered_map<boost::string_ref, std::vector<SharedFilter>, util::string::StringRefICaseHash, util::string::StringRefIEquals> m_typedIncludeRules;

					/// <summary>
					/// Used for storing exclusion filters which contain settings that bind the filters
					/// in this container to only match specific content types, among other things. Such
					/// rules cannot possibly be matched reliably when checking the request portion
					/// of a transaction only, so the rules are separated as to not be accessed when
					/// only a request is supplied to any ::ShouldBlock* methods.
					/// 
					/// This container holds both host-specific and global (no domain specified)
					/// filters. All global filters use the key "*", while all other host-bound
					/// rules use the host domain name, with no protocol or service applied
					/// (http://, https://, www.) as the key.
					/// </summary>
					std::unordered_map<boost::string_ref, std::vector<SharedFilter>, util::string::StringRefICaseHash, util::string::StringRefIEquals> m_typedExcludeRules;

					/// <summary>
					/// Used for storing selectors which are meant to hide/remove specific elements
					/// on websites. These selectors can be bound to a certain domain, or be
					/// specified for global use. When global use is desired, the key to be used is
					/// "*", which is stored in the member m_globalRuleKey. Whatever the value, the
					/// specified domain will serve as the key to this hashmap where all selectors
					/// for the specified domain/key are to be stored.
					/// </summary>
					std::unordered_map<boost::string_ref, std::vector<SharedCategorizedCssSelector>, util::string::StringRefICaseHash, util::string::StringRefIEquals> m_inclusionSelectors;

					/// <summary>
					/// Used for storing selectors which are meant to whitelist specific elements on
					/// websites from hiding and/or removal. These selectors can be bound to a
					/// certain domain, or be specified for global use. When global use is desired,
					/// the key to be used is "*", which is stored in the member m_globalRuleKey.
					/// Whatever the value, the specified domain will serve as the key to this
					/// hashmap where all selectors for the specified domain/key are to be stored.
					/// </summary>
					std::unordered_map<boost::string_ref, std::vector<SharedCategorizedCssSelector>, util::string::StringRefICaseHash, util::string::StringRefIEquals> m_exceptionSelectors;

					/// <summary>
					/// Holds all loaded text triggers. Text triggers are highly specific keywords
					/// meant to cat text of very specific categories, such as pornography. They
					/// don't just have to be keywords, they would also for example be domains. These
					/// triggers are searched for inside text payloads, include JSON.
					/// </summary>
					std::unordered_map<boost::string_ref, uint8_t, util::string::StringRefICaseHash, util::string::StringRefIEquals> m_textTriggers;

					/// <summary>
					/// Checks if the given payload has text triggers, and if one is found where the
					/// category is enabled, then the category for the matched trigger is returned.
					/// </summary>
					/// <param name="payload">
					/// The payload to check.
					/// </param>
					/// <returns>
					/// A non-zero value if the content should be blocked. Zero if the content should
					/// not be blocked.
					/// </returns>
					uint8_t ShouldBlockBecauseOfTextTrigger(const std::vector<char>& payload) const;

					/// <summary>
					/// Method that accepts a single Adblock Plus formatted filter or selector
					/// string. This method will process only part of the original string, splitting
					/// up any defined options and determining exactly what type of rule is being
					/// defined. Once these things have been established, the rule will be subbed
					/// out to subsequent methods which will continue parsing and ultimately
					/// building the rule into its appropriate object structure.
					/// 
					/// Note that this function is designed to return true if there were no errors
					/// detected while processing the rule, false otherwise. We strike a balance
					/// here between properly handling issues and allowing the program to continue
					/// when non critical errors occur. The type of error in mind here is when a
					/// rule that is not formatted correctly is encountered and cannot be processed.
					/// We want to alert the user that something did happen that should be
					/// investigated, but we don't want to explode the program because one or two
					/// rules out of thousands was broken.
					/// </summary>
					/// <param name="rule">
					/// A single filter or selector rule, written in Adblock Plus Filter syntax. 
					/// </param>
					/// <param name="category">
					/// The category that the rule is deemed to belong to (ads, malware, etc). 
					/// </param>
					/// <returns>
					/// True if the rule was successfully processed, false if not. 
					/// </returns>
					bool ProcessAbpFormattedRule(const std::string& rule, const uint8_t category);

					/// <summary>
					/// Adds an inclusion or exception selector, indexing it for use against only
					/// the supplied domains. An inclusion selector is used to hide/remove specific
					/// elements on one or more domains. Note that "*" can be supplied to add a
					/// selector that applies to all domains.
					/// </summary>
					/// <param name="domains">
					/// The domains, separated my commas or pipes ("," and "|") that the selector
					/// should apply to. "*" can be supplied to apply to all domains.
					/// </param>
					/// <param name="selector">The actual formatted CSS selector string.</param>
					/// <param name="category">
					/// The category that the selector is said to be long to. For example, ads,
					/// porn, etc.
					/// </param>
					void AddSelectorMultiDomain(boost::string_ref domains, const std::string& selector, const uint8_t category, const bool isException = false);

					/// <summary>
					/// Indexes an inclusion selector using the supplied domains as the key(s). This
					/// method is called by *MultiDomain(...) methods which delegates the job of
					/// doing the actual indexing to this function. This is just for the purpose of
					/// splitting up the logic to keep it more readible, simple and therefore
					/// maintainable. Without this separation the *MultiDomain(...) methods would
					/// get very ugly, complex, and begin to duplicate code within themselves.
					/// </summary>
					/// <param name="domain">
					/// The domain that the selector applies to. This can be "*" for selectors that
					/// apply to all domains.
					/// </param>
					/// <param name="selector">
					/// The constructed selector object.
					/// </param>
					void AddIncludeSelector(boost::string_ref domain, const SharedCategorizedCssSelector& selector);

					/// <summary>
					/// Indexes an exception selector using the supplied domains as the key(s). This
					/// method is called by *MultiDomain(...) methods which delegates the job of
					/// doing the actual indexing to this function. This is just for the purpose of
					/// splitting up the logic to keep it more readible, simple and therefore
					/// maintainable. Without this separation the *MultiDomain(...) methods would
					/// get very ugly, complex, and begin to duplicate code within themselves.
					/// </summary>
					/// <param name="domain">
					/// The domain that the selector applies to. This can be "*" for selectors that
					/// apply to all domains.
					/// </param>
					/// <param name="selector">
					/// The constructed selector object.
					/// </param>
					void AddExceptionSelector(boost::string_ref domain, const SharedCategorizedCssSelector& selector);

					/// <summary>
					/// Store a completed inclusion filter object appropriately, depending on its
					/// options.
					/// 
					/// Depending on the filtering rule, AddInclusionFilterMultiDomain(...) may or
					/// may not delegate the storage of a fully generated rule to this method. Where
					/// the rule should be stored might change depending on the options. Also, as
					/// noted in associated method descriptions, earlier stages in the rule parsing
					/// and building process may have determined that more than one rule needs to be
					/// generated for a single defined filtering rule string.
					/// 
					/// This is the reason for separating storage logic for individual rules from
					/// the AddXFilterMultiDomain(...) methods.
					/// </summary>
					/// <param name="domain">
					/// The domain that the filtering rule should belong to. This domain is used as
					/// the key for looking up domain specific rules quickly in a hash table.
					/// </param>
					/// <param name="filter">
					/// A shared_ptr to the completed inclusion filter object to be stored. 
					/// </param>
					void AddInclusionFilter(boost::string_ref domain, const SharedFilter& filter);

					/// <summary>
					/// Store a completed exception filter object appropriately, depending on its
					/// options.
					/// 
					/// Depending on the filtering rule, AddExceptionFilterMultiDomain(...) may or
					/// may not delegate the storage of a fully generated rule to this method. Where
					/// the rule should be stored might change depending on the options. Also, as
					/// noted in associated method descriptions, earlier stages in the rule parsing
					/// and building process may have determined that more than one rule needs to be
					/// generated for a single defined filtering rule string.
					/// 
					/// This is the reason for separating storage logic for individual rules from
					/// the AddXFilterMultiDomain(...) methods.
					/// </summary>
					/// <param name="domain">
					/// The domain that the filtering rule should belong to. This domain is used as
					/// the key for looking up domain specific rules quickly in a hash table.
					/// </param>
					/// <param name="filter">
					/// A shared_ptr to the completed exception filter object to be stored. 
					/// </param>
					void AddExceptionFilter(boost::string_ref domain, const SharedFilter& filter);

					/// <summary>
					/// Gets just the host name from a complete HTTP request URL.
					/// </summary>
					/// <param name="url">
					/// The url which may or may not contain additional preceeding characters not
					/// necessary for rule lookups.
					/// </param>
					boost::string_ref ExtractHostNameFromUrl(boost::string_ref url) const;

					/// <summary>
					/// Fetch the text content of the supplied, parsed HTML document.
					/// </summary>
					/// <param name="node">
					/// A valid pointer to a gq::Document from where to begin recursively extracting
					/// text content.
					/// </param>
					/// <returns>
					/// The text data of the supplied document and all of its children text nodes.
					/// </returns>
					std::string ExtractHtmlText(const gq::Document* document) const;

					/// <summary>
					/// Since it's possible for the user load many different filtering rules spanning
					/// many files, each containing potentially tens of thousands of rules, each rule
					/// potentially being for the same host, it makes sense to avoid copying the same
					/// information across this class. Further, to avoid unecessary copies of of such
					/// data to and from this object from request headers and such, we use
					/// boost::string_ref for storing such strings. However, in order to ensure that
					/// the string_ref objects stay valid, the original source string must be stored
					/// once, and only once to preserve its life, then a corresponding string_ref
					/// object generated around that string around the memory space where it's
					/// "permanently" stored.
					///
					/// This method transparently handles this process, returning a "preserved"
					/// version of a string_ref supplied to it. The string value however is converted
					/// to upper case before storage, so all returned values from this method are
					/// upper-case. These strings should be used in case-insensitive ways.
					/// </summary>
					/// <param name="original">
					/// The string_ref to preserve.
					/// </param>
					/// <returns>
					/// A boost::string_ref where the underlying string data is guaranteed to be
					/// preserved during the lifetime of this object.
					/// </returns>
					boost::string_ref GetPreservedICaseStringRef(boost::string_ref original);

					/// <summary>
					/// If an appropriate callback was supplied at construction, reports information
					/// about blocked requests to the supplied callback.
					/// </summary>
					/// <param name="category">
					/// The category to which the blocking rule belongs.
					/// </param>
					/// <param name="payloadSizeBlocked">
					/// The size of the response payload blocked from being downloaded.
					/// </param>
					/// <param name="host">
					/// The full request that was blocked.
					/// </param>
					void ReportRequestBlocked(const uint8_t category, const uint32_t payloadSizeBlocked, boost::string_ref fullRequest) const;

					/// <summary>
					/// If an appropriate callback was supplied at construction, reports information
					/// about blocked HTML elements to the supplied callback.
					/// </summary>
					/// <param name="numElementsRemoved">
					/// The number of HTML elements removed from the processed HTML response payload.
					/// </param>
					/// <param name="fullRequest">
					/// The full request that generated the filtered HTML response payload.
					/// </param>
					void ReportElementsBlocked(const uint32_t numElementsRemoved, boost::string_ref fullRequest) const;

				};

			} /* namespace http */
		} /* namespace filtering */
	} /* namespace httpengine */
} /* namespace te */