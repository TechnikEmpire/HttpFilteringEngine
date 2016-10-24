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

#include <cstring>
#include <vector>
#include <locale>
#include <boost/algorithm/string.hpp>
#include <boost/utility/string_ref.hpp>
#include <boost/functional/hash.hpp>

namespace te
{
	namespace httpengine
	{
		namespace util
		{
			namespace string
			{

				/// <summary>
				/// Compares the two string_ref objects for exact, case-sensitive equality.
				/// </summary>
				/// <param name="lhs">
				/// First string to compare against the second.
				/// </param>
				/// <param name="rhs">
				/// Second string to compare against the first.
				/// </param>
				/// <returns>
				/// True if both strings match exactly, false otherwise.
				/// </returns>
				inline bool Equal(boost::string_ref lhs, boost::string_ref rhs)
				{
					auto lhssize = lhs.size();
					auto rhssize = rhs.size();

					if (lhssize != rhssize)
					{
						return false;
					}

					if (lhssize >= 4)
					{
						// For longer strings, we'll quickly eliminate without doing full mem compare.
						// Also, we bypass the string_ref::compare() method because it does additional
						// checks, including size checks and such which is a waste, since we've already
						// done this externally.
						if ((lhs[0] == rhs[0]) &&
							(lhs[1] == rhs[1]) &&
							(lhs[lhssize - 1] == rhs[lhssize - 1]) &&
							(lhs[lhssize - 2] == rhs[lhssize - 2]))
						{
							
							return std::memcmp(lhs.begin(), rhs.begin(), lhssize) == 0;
						}
					}
					else
					{
						return std::memcmp(lhs.begin(), rhs.begin(), lhssize) == 0;
					}

					return false;
				}

				/// <summary>
				/// Splits the supplied string_ref by the supplied character delimiter.
				/// </summary>
				/// <param name="what">
				/// The string_ref to split.
				/// </param>
				/// <param name="delim">
				/// The delimiter.
				/// </param>
				/// <returns></returns>
				inline std::vector<boost::string_ref> Split(boost::string_ref what, const char delim)
				{
					std::vector<boost::string_ref> ret;

					auto i = what.find(delim);
					while (i != boost::string_ref::npos && (i != (what.size() - 1)))
					{
						if (i == 0)
						{
							// This is a little super-de-dangerous because only nullptr lies beneath.
							ret.push_back(boost::string_ref());
							what = what.substr(i + 1);
							continue;
						}

						auto ss = what.substr(0, i);

						what = what.substr(i + 1);

						ret.push_back(ss);

						i = what.find(delim);
					}

					return ret;
				}

				/// <summary>
				/// Hash implementation for string_ref.
				/// </summary>
				struct StringRefHash
				{
					size_t operator()(const boost::string_ref strRef) const
					{
						return boost::hash_range(strRef.begin(), strRef.end());
					}
				};
			
				inline size_t Hash(boost::string_ref ref)
				{
					return boost::hash_range(ref.begin(), ref.end());
				}

				/// <summary>
				/// Case-insensitive hash implementation for string_ref. Taken from boost docs here:
				/// http://www.boost.org/doc/libs/1_62_0/doc/html/unordered/hash_equality.html
				/// </summary>
				struct StringRefICaseHash : std::unary_function<boost::string_ref, std::size_t>
				{
					size_t operator()(const boost::string_ref strRef) const
					{
						std::size_t seed = 0;
						std::locale locale;

						for (boost::string_ref::const_iterator it = strRef.begin(); it != strRef.end(); ++it)
						{	
							boost::hash_combine(seed, std::toupper((*it), locale)); //locale
						}

						return seed;
					}
				};

				/// <summary>
				/// Case-insensitive equality predicate for string_ref. Taken from boost docs here:
				/// http://www.boost.org/doc/libs/1_62_0/doc/html/unordered/hash_equality.html
				/// </summary>
				struct StringRefIEquals : std::binary_function<boost::string_ref, boost::string_ref, bool>
				{
					bool operator()(const boost::string_ref lhs, const boost::string_ref rhs) const
					{
						return boost::algorithm::iequals(lhs, rhs); //std::locale()
					}
				};

			} /* namespace string */
		} /* namespace util */
	} /* namespace httpengine */
} /* namespace te */