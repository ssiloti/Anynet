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
#ifndef NAME_HPP
#define NAME_HPP

#include <link.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/cstdint.hpp>
#include <vector>

class content_name
{
	friend bool operator<(const content_name&, const content_name&);
	friend bool operator==(const content_name&, const content_name&);

	typedef std::vector<std::vector<boost::uint8_t> > components_t;

public:
	content_name() {}

	content_name(const_buffer buf)
	{
		parse(buf);
	}

	void add_component(const std::vector<boost::uint8_t>& comp)
	{
		components_.push_back(comp);
	}

	template <typename Handler>
	void receive(unsigned component_count, net_link& link, Handler handler)
	{
		if (component_count) {
			components_.resize(component_count);
			receive_component(components_.begin(), link, handler, boost::system::error_code(), 0);
		}
		else {
			handler(boost::system::error_code());
		}
	}

	std::size_t component_count() const { return components_.size(); }

	std::size_t serialize(mutable_buffer dest, bool inc_ccount = true) const
	{
		std::size_t total_size = inc_ccount ? 1 : 0;
		for (components_t::const_iterator comp = components_.begin(); comp != components_.end(); ++comp)
			total_size += comp->size() + 1;

		if (buffer_size(dest) == 0)
			return total_size;

		assert(buffer_size(dest) >= total_size);

		boost::uint8_t* comp_buf = buffer_cast<boost::uint8_t*>(dest);
		if (inc_ccount)
			*comp_buf++ = components_.size();
		for (components_t::const_iterator comp = components_.begin(); comp != components_.end(); ++comp) {
			*comp_buf = comp->size();
			std::memcpy(++comp_buf, comp->data(), comp->size());
			comp_buf += comp->size();
		}

		return total_size;
	}

	std::size_t serialize(uint8_t* dest)
	{
		std::size_t total_size = 1;

		*dest++ = components_.size();
		for (components_t::const_iterator comp = components_.begin(); comp != components_.end(); ++comp) {
			*dest = comp->size();
			std::memcpy(++dest, comp->data(), comp->size());
			dest += comp->size();
			total_size += comp->size();
		}

		return total_size;
	}

	std::size_t parse(const_buffer buf)
	{
		const boost::uint8_t* cursor = buffer_cast<const boost::uint8_t*>(buf);

		components_.resize(*cursor++);

		for (components_t::iterator comp = components_.begin(); comp != components_.end(); ++comp) {
			comp->resize(*cursor);
			std::memcpy(comp->data(), cursor + 1, *cursor);
			cursor += *cursor + 1;
		}

		return std::size_t(cursor - buffer_cast<const boost::uint8_t*>(buf));
	}

	std::size_t parse(const boost::uint8_t* buf)
	{
		const boost::uint8_t* cursor = buf;

		components_.resize(*cursor++);

		for (components_t::iterator comp = components_.begin(); comp != components_.end(); ++comp) {
			comp->resize(*cursor);
			std::memcpy(comp->data(), cursor + 1, *cursor);
			cursor += *cursor + 1;
		}

		return std::size_t(cursor - buf);
	}

private:


	template <typename Handler>
	void receive_component(components_t::iterator comp,
	                       net_link& link,
	                       Handler handler,
	                       const boost::system::error_code& error,
	                       std::size_t bytes_transferred)
	{
		if (error) {
			handler(error);
			return;
		}

		link.received(bytes_transferred);

		int bytes_needed = 1;

		if (link.valid_received_bytes() >= 1) {
			const boost::uint8_t* comp_buf = buffer_cast<const boost::uint8_t*>(link.received_buffer());

			if (link.valid_received_bytes() >= *comp_buf) {
				comp->resize(*comp_buf);
				std::memcpy(comp->data(), comp_buf + 1, *comp_buf);
				link.consume_receive_buffer(*comp_buf + 1);
				if (++comp == components_.end())
					handler(error);
				else
					receive_component(comp, link, handler, error, 0);
				return;
			}
			else {
				bytes_needed += *comp_buf - link.valid_received_bytes();
			}
		}

		boost::asio::async_read(link.socket,
		                        mutable_buffers_1(link.receive_buffer(bytes_needed)),
		                        boost::asio::transfer_at_least(bytes_needed),
		                        boost::bind(&content_name::receive_component<Handler>,
		                                    this,
		                                    comp,
		                                    boost::ref(link),
		                                    handler,
		                                    placeholders::error,
		                                    placeholders::bytes_transferred));
	}

	components_t components_;
};

inline bool operator==(const content_name& l, const content_name& r)
{
	return l.components_ == r.components_;
}

inline bool operator<(const content_name& l, const content_name& r)
{
	return l.components_ < r.components_;
}

#endif
