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

#include <boost/asio/ssl.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/placeholders.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/detail/endian.hpp>
#include <boost/cstdint.hpp>
#include <vector>

namespace ip = boost::asio::ip;
namespace placeholders = boost::asio::placeholders;

using boost::asio::const_buffer;
using boost::asio::mutable_buffer;
using boost::asio::const_buffers_1;
using boost::asio::mutable_buffers_1;
using boost::asio::buffer_cast;
using boost::asio::buffer_size;
using boost::asio::buffer;

using boost::uint8_t;
using boost::uint16_t;
using boost::uint32_t;
using boost::uint64_t;

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

template <typename I>
inline I hton(I i)
{
	return I::hton(i);
}

template <>
inline boost::uint16_t hton(boost::uint16_t i)
{
	return htons(i);
}

template <>
inline boost::uint32_t hton(boost::uint32_t i)
{
	return htonl(i);
}

template <>
inline boost::uint64_t hton(boost::uint64_t i)
{
#ifdef BOOST_LITTLE_ENDIAN
	#ifdef BOOST_MSVC
	return _byteswap_uint64(i);
	#else
	return bswap_64(i);
	#endif
#else
	return i;
#endif
}

class net_link
{
public:
	static const std::size_t sr_buffer_size = 8192;
	static const int protocol_version = 0;

	typedef std::vector<boost::uint8_t> sr_buffer_t;
	typedef boost::asio::ssl::stream<ip::tcp::socket> socket_t;

	net_link(boost::asio::io_service& io_service, boost::asio::ssl::context& ctx)
		: socket(io_service, ctx)
		, valid_receive_bytes_(0)
		, valid_send_bytes_(0)
		, send_buffer_(sr_buffer_size)
	{}

	mutable_buffer receive_buffer(std::size_t size = 0)
	{
#if 0
		std::size_t old_size = receive_buffer_.size();
		std::size_t add_size = std::max(size, sr_buffer_size);
		receive_buffer_.resize(old_size + add_size);
		return mutable_buffer(&receive_buffer_[old_size], add_size);
#else
		if (receive_buffer_.size() < valid_receive_bytes_ + std::max(size, sr_buffer_size))
			receive_buffer_.resize(valid_receive_bytes_ + std::max(size, sr_buffer_size));
		return mutable_buffer(&receive_buffer_[valid_receive_bytes_], std::max(size, sr_buffer_size));
#endif
	}

	const_buffer received_buffer()
	{
		return const_buffer(&receive_buffer_[0], valid_receive_bytes_);
	}

	std::size_t valid_received_bytes()
	{
		return valid_receive_bytes_;
	}

	template <typename Handler>
	void make_valid(std::size_t bytes, Handler handler)
	{
		if (valid_received_bytes() >= bytes)
			handler(boost::system::error_code(), 0);
		else
			boost::asio::async_read(socket,
			                        mutable_buffers_1(receive_buffer(bytes)),
			                        boost::asio::transfer_at_least(bytes - valid_received_bytes()),
			                        handler);
	}

	template <typename Handler>
	void receive_into(std::vector<mutable_buffer> bufs, Handler handler)
	{
		std::vector<mutable_buffer>::iterator begin = bufs.begin();
		while (begin != bufs.end()) {
			std::size_t consumed = std::min(valid_received_bytes(), buffer_size(*begin));
			DLOG(INFO) << "Consuming " << consumed;
			std::memcpy(buffer_cast<void*>(*begin),
			            buffer_cast<const void*>(received_buffer()),
			            consumed);
			consume_receive_buffer(consumed);
			if (consumed == buffer_size(*begin))
				++begin;
			else {
				(*begin) = (*begin) + consumed;
				break;
			}
		}

		if (begin != bufs.end()) {
			bufs.erase(bufs.begin(), begin);
			boost::asio::async_read(socket,
			                        bufs,
			                        handler);
		}
		else {
			handler(boost::system::error_code(), 0);
		}
	}

	void consume_receive_buffer(std::size_t bytes)
	{
		valid_receive_bytes_ -= bytes;
#if 0
		receive_buffer_.erase(receive_buffer_.begin(), receive_buffer_.begin() + bytes);
#else
		std::memmove(&receive_buffer_[0], &receive_buffer_[bytes], valid_receive_bytes_);
#endif
		DLOG(INFO) << "Consumed " << bytes << " bytes";
	}

	void received(std::size_t bytes)
	{
#if 0
		receive_buffer_.resize(valid_receive_bytes_ += bytes);
#else
		valid_receive_bytes_ += bytes;
		DLOG(INFO) << "Received " << bytes << " bytes";
#endif
	}

	mutable_buffer send_buffer(std::size_t size = sr_buffer_size)
	{
#if 0
		std::size_t old_size = send_buffer_.size();
		send_buffer_.resize(old_size + size);
		return mutable_buffer(&send_buffer_[old_size], size);
#else
		std::size_t old_size = valid_send_bytes_;
		valid_send_bytes_ += size;
		return mutable_buffer(&send_buffer_[old_size], size);
#endif
	}

	const_buffer sendable_buffer()
	{
		return mutable_buffer(&send_buffer_[0], valid_send_bytes_);
	}

	void clear_send_buffer()
	{
		valid_send_bytes_ = 0;
	}

	socket_t socket;

private:
	std::size_t valid_receive_bytes_;
	std::size_t valid_send_bytes_;
	sr_buffer_t receive_buffer_;
	sr_buffer_t send_buffer_;
};

#endif