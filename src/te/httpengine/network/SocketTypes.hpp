/*
* Copyright © 2017 Jesse Nicholson
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/


#pragma once

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

namespace te
{
	namespace httpengine
	{
		namespace network
		{

			using TcpSocket = boost::asio::ip::tcp::socket;
			using TlsSocket = boost::asio::ssl::stream<TcpSocket>;

		} /* namespace network */
	} /* namespace httpengine */
} /* namespace te */