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

#ifndef FRAGMENTED_CONTENT_HPP
#define FRAGMENTED_CONTENT_HPP

#include "user_content_fwd.hpp"
#include <core.hpp>
#include <list>

namespace user_content
{

class framented_content
{
public:
	typedef boost::shared_ptr<framented_content> ptr_t;

	struct fragment_buffer
	{
		friend class framented_content;
		const std::size_t offset;
		const mutable_buffer buf;
		const payload_buffer_ptr content;

		fragment_buffer(std::size_t o = 0, std::size_t s = 0, payload_buffer_ptr c = payload_buffer_ptr())
			: content(c)
			, offset(o)
			, buf(buffer(c->get() + o, s))
		{}
	};

	framented_content(payload_buffer_ptr c)
		: content_(c)
	{
		invalid_.push_back(fragment(0, buffer_size(c->get()), ip::address(), fragment::invalid));
	}

	std::pair<std::size_t, std::size_t> next_invalid_range();
	fragment_buffer get_fragment_buffer(std::size_t offset, std::size_t size);
	void mark_valid(boost::shared_ptr<frame_fragment> frag, ip::address source);
	const_payload_buffer_ptr complete();
	void reset();

private:
	struct fragment
	{
		enum fragment_state
		{
			invalid,
			requested,
			receiving,
			valid,
		};

		fragment(std::size_t o, std::size_t s, ip::address src, fragment_state st)
			: offset(o)
			, size(s)
			, source(src)
			, state(st)
		{}

		std::size_t offset, size;
		fragment_state state;
		ip::address source;
	};
	std::list<fragment> valid_;
	std::list<fragment> requested_;
	std::list<fragment> receiving_;
	std::list<fragment> invalid_;
	payload_buffer_ptr content_;
};

}

#endif
