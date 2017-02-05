/*
* Copyright © 2017 Jesse Nicholson
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <vector>
#include <algorithm>
#include "HttpFilteringOptions.hpp"

namespace te
{
	namespace httpengine
	{
		namespace filtering
		{
			namespace options
			{
				/// <summary>
				/// This class is meant to serve as the storage and controller for the values of
				/// program wide options. Fortunately, all of the options are very simple, they're
				/// either true or false. It is up to the library implementer to load/store these
				/// values.
				/// 
				/// This library is designed to be implemented into a complete user application with
				/// a graphical user iterface. A simple medium is therefore required where the user
				/// may interactively modify the functionality provided in this library. The
				/// implementation is simple, atomic boolean arrays using strongly typed enums which
				/// are cast to the indices of the arrays, with getter/setter methods provided.
				/// 
				/// This class however is not meant to be provided to implementers/consumers.
				/// Rather, this class should be kept behind a C style API or, in the case of the
				/// C# WPF application, hidden behind a CLR class interface.
				/// </summary>
				class ProgramWideOptions
				{

				public:

					/// <summary>
					/// Default constructor.
					/// </summary>
					ProgramWideOptions(const std::string& blockedPageHtml);

					/// <summary>
					/// No copy no move no thx.
					/// </summary>					
					ProgramWideOptions(const ProgramWideOptions&) = delete;
					ProgramWideOptions(ProgramWideOptions&&) = delete;
					ProgramWideOptions& operator=(const ProgramWideOptions&) = delete;
					
					/// <summary>
					/// Default destructor.
					/// </summary>
					~ProgramWideOptions();

					/// <summary>
					/// Check if the specified category is enabled for HTTP filtering. HTTP
					/// filtering in this engine includes a number of categories and includes more
					/// than filtering requests by the request strings or domains. HTTP filtering
					/// also includes filtering content defined to be in certain categories based on
					/// the actual content of the http transaction payload. The categories of these
					/// contents are determined by things such as Natural Language Processing
					/// (document classification), content association (content X links to content Y
					/// which is known to be in category Z), etc.
					/// 
					/// This is meant to be a simple interface to a thread-safe storage system of
					/// boolean values, made available to an implementer of this library (such as a
					/// GUI) so that real time control over how the library engine(s) function is
					/// possible.
					/// </summary>
					/// <param name="category">
					/// The HTTP filtering category to query. 
					/// </param>
					/// <returns>
					/// True if the category is enabled, meaning that content found in this category
					/// will be blocked, false otherwise.
					/// </returns>
					bool GetIsHttpCategoryFiltered(const uint8_t category) const;

					/// <summary>
					/// Set if the specified category is enabled for HTTP filtering. HTTP
					/// filtering in this engine includes a number of categories and includes more
					/// than filtering requests by the request strings or domains. HTTP filtering
					/// also includes filtering content defined to be in certain categories based on
					/// the actual content of the http transaction payload. The categories of these
					/// contents are determined by things such as Natural Language Processing
					/// (document classification), content association (content X links to content Y
					/// which is known to be in category Z), etc.
					/// 
					/// This is meant to be a simple interface to a thread-safe storage system of
					/// boolean values, made available to an implementer of this library (such as a
					/// GUI) so that real time control over how the library engine(s) function is
					/// possible.
					/// </summary>
					/// <param name="category">
					/// The HTTP filtering category to modify the value of. 
					/// </param>
					/// <param name="value">
					/// The value to be set for the supplied category.
					/// </param>
					void SetIsHttpCategoryFiltered(const uint8_t category, const bool value);

					/// <summary>
					/// Check if the specified HTTP filtering option is enabled or not. Aside from
					/// filtering content by category, the HTTP filtering engine provides some
					/// additional functionality which can be enabled or disabled. For example, it's
					/// possible to specify that all "Referer" HTTP headers are never sent outbound
					/// from the proxy, since this is one of the most persistent, basic and invasive
					/// forms of tracking done on the web today.
					/// 
					/// This is meant to be a simple interface to a thread-safe storage system of
					/// boolean values, made available to an implementer of this library (such as a
					/// GUI) so that real time control over how the library engine(s) function is
					/// possible.
					/// </summary>
					/// <param name="option">
					/// The HTTP filtering option to query.
					/// </param>
					/// <returns>
					/// True if the option is enabled, false otherwise.
					/// </returns>
					bool GetIsHttpFilteringOptionEnabled(const http::HttpFilteringOption option) const;

					/// <summary>
					/// Set if the specified HTTP filtering option is enabled or not. Aside from
					/// filtering content by category, the HTTP filtering engine provides some
					/// additional functionality which can be enabled or disabled. For example, it's
					/// possible to specify that all "Referer" HTTP headers are never sent outbound
					/// from the proxy, since this is one of the most persistent, basic and invasive
					/// forms of tracking done on the web today.
					/// 
					/// This is meant to be a simple interface to a thread-safe storage system of
					/// boolean values, made available to an implementer of this library (such as a
					/// GUI) so that real time control over how the library engine(s) function is
					/// possible.
					/// </summary>
					/// <param name="option">
					/// The HTTP filtering option to modify.
					/// </param>
					/// <param name="value">
					/// The value to be set for the supplied HTTP filtering option.
					/// </param>
					void SetIsHttpFilteringOptionEnabled(const http::HttpFilteringOption option, const bool value);

					/// <summary>
					/// Gets the user-defined HTML page to display when a HTML page is blocked.
					/// </summary>
					/// <returns>
					/// The bytes for the user-defined HTML page to display when a HTML page is
					/// blocked. This is uncompressed, and can/should simply be assigned to response
					/// payloads.
					/// </returns>
					std::vector<char> GetHtmlBlockedPagePayload() const;

				private:

					/// <summary>
					/// Hold the state of enabled or disabled http filtering categories. The idea
					/// here is you simply access the option of the fixed size array using the
					/// provided keys/indices for getting/setting the current value in a thread-safe
					/// way.
					/// </summary>
					std::array<std::atomic_bool, std::numeric_limits<uint8_t>::max()> m_httpContentFilteringCategories;

					/// <summary>
					/// Hold the state of enabled or disabled http filtering options. The idea
					/// here is you simply access the option of the fixed size array using the
					/// provided keys/indices for getting/setting the current value in a thread-safe
					/// way.
					/// </summary>
					std::array<std::atomic_bool, static_cast<size_t>(http::HttpFilteringOption::NUMBER_OF_ENTRIES)> m_httpFilteringOptions;

					/// <summary>
					/// Holds the payload for the user-defined HTML blocked page.
					/// </summary>
					std::vector<char> m_htmlBlockPagePayload;

				};

			} /* namespace options */
		} /* namespace filtering */
	} /* namespace httpengine */
} /* namespace te */