/*
* Copyright © 2017 Jesse Nicholson
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
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