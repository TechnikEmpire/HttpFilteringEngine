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

#include <array>
#include <atomic>
#include <cstdint>
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
					ProgramWideOptions();

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

				};

			} /* namespace options */
		} /* namespace filtering */
	} /* namespace httpengine */
} /* namespace te */