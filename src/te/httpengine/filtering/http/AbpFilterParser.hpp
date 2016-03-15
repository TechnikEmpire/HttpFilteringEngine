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

#include "AbpFilter.hpp"
#include <unordered_map>
#include <memory>
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
				/// The AbpFilterParser class serves the purpose of accurately and rapidly parsing
				/// supplied strings into "compiled" Adblock Plus Filter objects, which are used for
				/// filtering requests based on host, URI and generated response payload content
				/// types.
				/// </summary>
				class AbpFilterParser : public util::cb::EventReporter
				{

				private:

					/// <summary>
					/// Contains all valid filter options. Used when parsing string options to
					/// quickly retrieve the correct corresponding AbpFilterOption value.
					/// </summary>
					static const std::unordered_map<boost::string_ref, AbpFilterOption, util::string::StringRefHash> ValidFilterOptions;

				public:

					using SharedFilter = std::shared_ptr<AbpFilter>;

					/// <summary>
					/// Constructs a new AbpFilterParser object instance.
					/// </summary>
					AbpFilterParser(
						util::cb::MessageFunction onInfo = nullptr,
						util::cb::MessageFunction onWarning = nullptr,
						util::cb::MessageFunction onError = nullptr
						);

					/// <summary>
					/// Default empty destructor.
					/// </summary>
					~AbpFilterParser();

					/// <summary>
					/// Attempts to parse the supplied filter string and "compile" it into an
					/// Adblock Plus Filter object that can be used for filtering requests based on
					/// host, URI and generated response payload content types. The parser will
					/// throw std::runtime_error by value with a detailed description of any
					/// encountered issue in the event that the supplied filter string contains
					/// errors.
					/// 
					/// In the event that an exception is thrown by any internal parsing method, the
					/// error will be caught within the ::Parse(...) function, where a string
					/// pointing to the precise location of the error within the supplied filter
					/// string will be generated and the original exception will be rethrown,
					/// wrapped in this original data. This can/should greatly assist in debugging
					/// filters.
					/// </summary>
					/// <param name="filterString">
					/// The raw filtering string to parse.
					/// </param>
					/// <param name="category">
					/// The category that the filter is to be marked as belonging to.
					/// </param>
					/// <returns>
					/// A "compiled" and shared Adblock Plus Filter object.
					/// </returns>
					SharedFilter Parse(const std::string& filterString, const uint8_t category) const;

				private:					

					using FilterPart = AbpFilter::FilterPart;
					using SharedFilter = std::shared_ptr<AbpFilter>;				

					/// <summary>
					/// Attempt to extract the next unique filtering block from the supplied filter
					/// string. A "unique filtering block" is defined as a section of a filter
					/// string that is unique in its operation during the filter matching function.
					/// Examples of this are string literal matches, anchored domain matches,
					/// wildcard matches, etc. All of these are "unique filtering blocks" as they
					/// serve distinct, separate purposes in matching.
					/// 
					/// This method will attempt to identify and extract the next unique filtering
					/// block from the supplied string, returning that block combined with an
					/// enumeration that identifies its type. In the event that this method
					/// encouters invalid or improperly formatted data within the supplied filter
					/// string, it will throw a std::runtime_error populated with a string detailing
					/// the nature of the exception.
					/// </summary>
					/// <param name="filterStr">
					/// The filter string from which to attempt to extract the next (by left to
					/// right order) unique filtering block.
					/// </param>
					/// <param name="pos">
					/// The position from which to begin searching.
					/// </param>
					/// <returns>
					/// A tuple composed of the extracted block string data and a enumeration which
					/// identifies the type of block parsed.
					/// </returns>
					FilterPart ParseFilterPart(boost::string_ref& filterStr, const boost::string_ref::size_type pos = 0) const;

					/// <summary>
					/// Parses any settings found in the supplied filter string and returns a
					/// HttpAbpFilterSettings object where each setting is represented in a
					/// collection of bits. Note that the HttpAbpFilterSettings object does not
					/// contain members for every single possible Adblock Plus Filter option. Some
					/// options are omitted due to a lack of support within this Engine, and some,
					/// such as applicable domains, are omitted as they must be collected through a
					/// separate, defined process.
					/// </summary>
					/// <param name="optionsString">
					/// The The options section of a filter string from which to attempt to parse
					/// the filter settings.
					/// </param>
					/// <returns>
					/// In the event that options were found in the supplied filter string that can
					/// be represented by the members of the HttpAbpFilterSettings object, a
					/// HttpAbpFilterSettings with bits set according to the parsed filter options.
					/// In the event that no such options are found in the supplied filter string, a
					/// HttpAbpFilterSettings object with all bits set to false.
					/// </returns>
					AbpFilterSettings ParseSettings(boost::string_ref optionsString) const;

					/// <summary>
					/// Extracts all domains from the supplied filter that the filter should or
					/// should not apply to, depending on the exceptions parameter value.. This
					/// method simply searches for the "$domain" Adblock Plus Filter option in the
					/// supplied string and, again depending on whether the user has specified via
					/// the exceptions option that they would like exception or inclusion domains,
					/// returns any and all such domains.
					/// 
					/// Note that in the event that the filtering rule is an inclusion filter
					/// (blocking), and an empty collection is returned, and the same filtering rule
					/// contains no inclusion domains (domains that the rule is specified as being
					/// able to function on), then the rule should be treated as if it has no domain
					/// exceptions at all. The rule is globally applicable.
					/// 
					/// If the filtering rule is an inclusion filter (blocking), and an empty
					/// collection is returned here but the same filtering rule produces inclusion
					/// domains (domains that the rule is specified as being able to function on),
					/// then the filtering rule should be treated as only applicable to the
					/// inclusion domains returned. That is, the rule is not globally applicable,
					/// but only applicable on the specified inclusion domains.
					/// 
					/// If the filtering rule is an exception rule itself, then exception domains
					/// returned here should invert the function of the exception rule into an
					/// inclusion filter for the domains returned from this function. This is not
					/// specifically stated in any Adblock Plus documentation that I am aware of,
					/// and I have not need a single line of Adblock Plus code, but the logic
					/// follows.
					/// 
					/// XXX TODO - It might be sufficient and logically sound to simply deactivate
					/// the exception filter on the exception domain, but this action can only be
					/// taken to explicitly allow a matching request to be blocked (by not
					/// whitelisting it), so going the extra step and inverting seems logical, but
					/// perhaps this needs more pondering.
					/// </summary>
					/// <param name="optionsString">
					/// The options section of a filter string from which to extract any and all
					/// domains included in the filter options that are marked as exception domains.
					/// </param>
					/// <param name="exceptions">
					/// Indicate whether we should be extracting only exception domains, or only
					/// inclusion domains. This function will not extract both into the same
					/// collection.
					/// </param>
					/// <returns>
					/// A collection of either inclusion or exception domains found in the supplied
					/// filtering options string, according to which type the user requested via the
					/// exceptions parameter. If no domains of the type specified
					/// (exception/inclusion) were found, an empty vector will be returned. Note
					/// that if the value of exceptions provided is false, and no inclusion domains
					/// were found, the collection will not be returned empty, but rather contain a
					/// single entry of "*". Rules are globally inclusive if one or more inclusion
					/// domains are not specified in the rule options.
					/// </returns>
					std::unordered_set<boost::string_ref, util::string::StringRefHash> ParseDomains(boost::string_ref optionsString, const bool exceptions) const;

					/// <summary>
					/// Extracts the next comma separated string part from the front of the supplied
					/// string. Argument is pass by reference, as the the method consumes the part
					/// it returns.
					/// </summary>
					/// <param name="optionsString">
					/// The options section of a filter string from which to extract comma separated
					/// option values.
					/// </param>
					/// <returns>
					/// The next comma separated part from the front of the string. If the string is
					/// not empty and no comma is present, the entire contents of the supplied
					/// string will be returned. The content returned from the this function, when
					/// the length is greater than zero, is always consumed from the supplied option
					/// string.
					/// </returns>
					boost::string_ref ParseSingleOption(boost::string_ref& optionsString) const;
				};

			} /* namespace http */
		} /* namespace filtering */
	} /* namespace httpengine */
} /* namespace te */
