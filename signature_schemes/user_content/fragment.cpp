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
#include "node.hpp"

using namespace user_content;

struct packed_fragment_header
{
	boost::uint8_t frame_type;
	boost::uint8_t rsvd0;
	boost::uint8_t protocol[2];
	boost::uint8_t status_name_components;
	boost::uint8_t rsvd1[3];
	boost::uint8_t key[network_key::packed_size];
	boost::uint8_t offset[8];
	boost::uint8_t size[8];
};

std::size_t frame_fragment::header_size()
{
	return sizeof(packed_fragment_header);
}

std::size_t frame_fragment::serialize_header(mutable_buffer buf)
{
	packed_fragment_header* h = buffer_cast<packed_fragment_header*>(buf);

	h->frame_type = content_protocol::frame_type_fragment;
	u16(h->protocol, protocol_);
	h->status_name_components = id_.name.component_count() | (status() << 6);
	id_.publisher.encode(h->key);
	u64(h->offset, offset_);
	u64(h->size, size_);

#if _DEBUG
	h->rsvd0 = 0xAA;
	h->rsvd1[0] = h->rsvd1[1] = h->rsvd1[2] = 0xBB;
#else
	h->rsvd0 = 0;
	h->rsvd1[0] = h->rsvd1[1] = h->rsvd1[2] = 0;
#endif

	return sizeof(packed_fragment_header) + id_.name.serialize(buf + sizeof(packed_fragment_header), false);
}

unsigned frame_fragment::parse_header(const_buffer buf)
{
	const packed_fragment_header* h = buffer_cast<const packed_fragment_header*>(buf);

	protocol_ = u16(h->protocol);
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

	return h->status_name_components & 0x3F;
}

std::vector<const_buffer> frame_fragment::serialize(std::size_t threshold, mutable_buffer scratch)
{
	DLOG(INFO) << "Sending fragment id=" << std::string(id().publisher);
	assert(buffer_size(scratch) >= sizeof(packed_fragment_header));

	std::vector<const_buffer> buffers;
	buffers.push_back(buffer(scratch, serialize_header(scratch)));

	if (status_ == status_attached) {
		std::size_t payload_size = std::min(size_, std::max(threshold, std::size_t(2048)));
		buffers.push_back(buffer(payload_->get() + offset_, payload_size));
		offset_ += payload_size;
		size_ -= payload_size;
	}

	return buffers;
}

void frame_fragment::send_failure(local_node& node, const network_key& dest)
{
	to_reply();
	static_cast<content_protocol*>(&node.get_protocol(protocol_))->snoop_fragment(dest, shared_from_this());
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
