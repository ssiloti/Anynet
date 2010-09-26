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

#include "fragmented_content.hpp"

using namespace user_content;

std::pair<std::size_t, std::size_t> framented_content::next_invalid_range()
{
	if (invalid_.empty())
		return std::make_pair(0, 0);
	return std::make_pair(invalid_.front().offset, invalid_.front().size);
}

framented_content::fragment_buffer framented_content::get_fragment_buffer(std::size_t offset, std::size_t size)
{
	// for now we will only allow one sequential receipt
	if (invalid_.empty() || !receiving_.empty() ||  offset != invalid_.front().offset)
		return fragment_buffer(offset);
	else {
		receiving_.push_back(fragment(offset, std::min(size, invalid_.front().size), ip::address(), fragment::receiving));
		invalid_.front().offset += receiving_.back().size;
		invalid_.front().size -= receiving_.back().size;
		if (invalid_.front().size == 0)
			invalid_.pop_front();
		return fragment_buffer(receiving_.back().offset, receiving_.back().size, content_);
	}
}

void framented_content::mark_valid(boost::shared_ptr<frame_fragment> frag, ip::address source)
{
	receiving_.front().source = source;
	valid_.push_back(receiving_.front());
	receiving_.pop_front();
}

const_payload_buffer_ptr framented_content::complete()
{
	if (invalid_.empty() && receiving_.empty() && requested_.empty())
		return content_;
	else
		return const_payload_buffer_ptr();
}

void framented_content::reset()
{
	invalid_.clear();
	valid_.clear();
	receiving_.clear();
	requested_.clear();
	invalid_.push_back(fragment(0, buffer_size(content_->get()), ip::address(), fragment::invalid));
}
