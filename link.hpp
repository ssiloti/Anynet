// anynet
// Copyright (C) 2009  Steven Siloti
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//
// In addition, as a special exception, the copyright holders give
// permission to link the code of portions of this program with the
// OpenSSL library under certain conditions as described in each
// individual source file, and distribute linked combinations
// including the two.
//
// You must obey the GNU General Public License in all respects
// for all of the code used other than OpenSSL.  If you modify
// file(s) with this exception, you may extend this exception to your
// version of the file(s), but you are not obligated to do so.  If you
// do not wish to do so, delete this exception statement from your
// version.  If you delete this exception statement from all source
// files in the program, then also delete it here.
//
// Contact:  Steven Siloti <ssiloti@gmail.com>

#ifndef LINK_HPP
#define LINK_HPP

#define _WIN32_WINNT 0x0501

#include <glog/logging.h>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/placeholders.hpp>
#include <boost/array.hpp>
#include <boost/cstdint.hpp>

namespace ip = boost::asio::ip;
namespace placeholders = boost::asio::placeholders;

template <typename Addr>
inline Addr to(ip::address a)
{
	return Addr::to(a);
}

template <>
inline ip::address_v4 to<ip::address_v4>(ip::address a)
{
	return a.to_v4();
}

template <>
inline ip::address_v6 to<ip::address_v6>(ip::address a)
{
	return a.to_v6();
}

struct net_link
{
	static const int sr_buffer_size = 8192;
	static const int protocol_version = 0;

	typedef boost::array<boost::uint8_t, sr_buffer_size> sr_buffer_t;

	net_link(boost::asio::io_service& io_service) : socket(io_service), valid_recv_bytes(0) {}

	void consume_receive_buffer(std::size_t bytes)
	{
		assert(bytes <= valid_recv_bytes);

		valid_recv_bytes -= bytes;

		if (valid_recv_bytes)
			std::memmove(receive_buffer.data(), receive_buffer.data() + bytes, valid_recv_bytes);
	}

	ip::tcp::socket socket;
	sr_buffer_t receive_buffer;
	sr_buffer_t send_buffer;

	size_t valid_recv_bytes;
};

#endif