/*
* Copyright © 2017 Jesse Nicholson
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

#pragma once

#include <string>
#include <cctype>
#include <algorithm>
#include <locale>
#include <boost/algorithm/string.hpp>
#include <boost/functional/hash.hpp>

namespace te
{
	namespace httpengine
	{
		namespace util
		{
			namespace hash
			{				
				struct ICaseStringHash
				{
					size_t operator()(const std::string& str) const
					{
						std::size_t seed = 0;
						std::locale locale;

						for (std::string::const_iterator it = str.begin(); it != str.end(); ++it)
						{
							boost::hash_combine(seed, std::toupper(*it, locale));
						}

						return seed;
					}
				};

				struct ICaseStringEquality
				{
					bool operator()(const std::string& str1, const std::string& str2) const
					{
						auto oneSize = str1.size();
						auto twoSize = str2.size();

						if (oneSize != twoSize)
						{
							return false;
						}

						std::locale locale;

						if (std::toupper(str1[0], locale) != std::toupper(str2[0], locale))
						{
							return false;
						}

						return boost::algorithm::iequals(str1, str2, locale);
					}
				};
			}
		}
	}
}