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

#include "fragment.hpp"
#include "connection.hpp"

struct packed_fragment_header
{
	boost::uint8_t frame_type;
	boost::uint8_t sig[2];
	boost::uint8_t status_name_components;
	boost::uint8_t key[network_key::packed_size];
	boost::uint8_t offset[8];
	boost::uint8_t size[8];
};

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

std::size_t frame_fragment::header_size()
{
	return sizeof(packed_fragment_header);
}

std::size_t frame_fragment::serialize_header(mutable_buffer buf)
{
	packed_fragment_header* h = buffer_cast<packed_fragment_header*>(buf);

	h->frame_type = connection::frame_fragment;
	u16(h->sig, protocol_);
	h->status_name_components = id_.name.component_count() | (status() << 6);
	id_.publisher.encode(h->key);
	u64(h->offset, offset_);
	u64(h->size, size_);

	return sizeof(packed_fragment_header) + id_.name.serialize(buf + sizeof(packed_fragment_header));
}

std::pair<std::size_t, unsigned> frame_fragment::parse_header(const_buffer buf)
{
	const packed_fragment_header* h = buffer_cast<const packed_fragment_header*>(buf);

	protocol_ = u16(h->sig);
	status_ = fragment_status(h->status_name_components >> 6);
	if (status_ == 2)
		status_ = status_failed;
	id_.publisher.decode(h->key);

	content_size_t size = u64(h->size), offset = u64(h->offset);

	if (offset + size > std::numeric_limits<std::size_t>::max() || offset + size < offset) {
		offset_ = size_ = 0;
	}
	else {
		offset_ = std::size_t(u64(h->offset));
		size_ = std::size_t(u64(h->size));
	}

	if (status_ == status_attached)
		return std::make_pair(size_, h->status_name_components & 0x3F);
	else
		return std::make_pair(0, h->status_name_components & 0x3F);
}

std::vector<const_buffer> frame_fragment::serialize(std::size_t threshold, mutable_buffer scratch)
{
	DLOG(INFO) << "Sending fragment id=" << std::string(id().publisher);
	assert(buffer_size(scratch) >= sizeof(packed_fragment_header));

	std::vector<const_buffer> buffers;
	buffers.push_back(buffer(scratch, serialize_header(scratch)));

	if (status_ == status_attached) {
		std::size_t payload_size = std::min(size_, threshold);
		buffers.push_back(buffer(payload_->get() + offset_, payload_size));
		offset_ += payload_size;
		size_ -= payload_size;
	}

	return buffers;
}

void frame_fragment::to_request(std::size_t o, std::size_t s)
{
	payload_ = const_payload_buffer_ptr();
	status_ = status_requested;
	offset_ = o;
	size_ = s;
}

void frame_fragment::to_reply(const_payload_buffer_ptr p)
{
	payload_ = p;
	status_ = status_attached;
}
