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

#include <cstdint>

namespace te
{
	namespace httpengine
	{
		namespace filtering
		{
			namespace options
			{
				namespace http
				{

					/// <summary>
					/// Enum used to define possible options specifically for HTTP filtering. These keys
					/// are meant to be used interally with the ProgramWideOptions object. For library
					/// implementers, these keys should be used from a provided option checking/setting
					/// API.
					/// 
					/// When making additions to this enum, values must not be explicitly assigned and
					/// NUMBER_OF_ENTRIES must always be the final entry.
					/// </summary>
					enum class HttpFilteringOption : uint32_t
					{
						RemoveReferer,
						StripGpsCoordinates,
						RemoveImageMetaData,
						UseDeepContentAnalysis,
						NUMBER_OF_ENTRIES
					};					

				}/* namespace http */
			} /* namespace options */
		} /* namespace filtering */
	} /* namespace httpengine */
} /* namespace te */