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

#include "packet.hpp"
#include "field_utils.hpp"
#include "connection.hpp"
#include <boost/asio/read.hpp>
#include <boost/bind.hpp>
#include <cstring>

/*
bool content_sources::source_cmp::operator()(const source& l, const source& r)
{
	if (!valid_dest)
		return l.ep < r.ep;

	return ::distance(network_key(l.ip), dest) < ::distance(network_key(r.ip), dest);
}*/

struct packed_header
{
	boost::uint8_t frame_type;
	boost::uint8_t protocol;
	boost::uint8_t rsvd[2];
	boost::uint8_t destination[network_key::packed_size];
	boost::uint8_t payload_size[4];
};

std::size_t packet::header_size()
{
	return sizeof(packed_header);
}

std::size_t packet::parse_header(const_buffer buf)
{
	const packed_header* header = buffer_cast<const packed_header*>(buf);

	content_status(content_status_t(header->protocol >> 6));
	protocol(header->protocol & 0x3F);
	destination(network_key(header->destination));
	return u32(header->payload_size);
}

std::size_t packet::serialize_header(mutable_buffer buf)
{
	packed_header* header = buffer_cast<packed_header*>(buf);
	
	header->frame_type = connection::frame_network_packet;
	header->protocol = protocol();
	header->protocol |= content_status() << 6;
	destination().encode(header->destination);

	return sizeof(packed_header);
}

std::vector<const_buffer> packet::serialize(std::size_t threshold,mutable_buffer scratch)
{
	DLOG(INFO) << "Sending packet dest=" << std::string(destination());

	std::vector<const_buffer> buffers;
	buffers.push_back(buffer(scratch, serialize_header(scratch)));

	if (payload_.get() != NULL) {
		const std::vector<const_buffer>& payload_buffers = payload_->serialize(shared_from_this(), threshold, scratch + buffer_size(buffers.back()));

		std::size_t payload_size = 0;
		for (std::vector<const_buffer>::const_iterator pbuf = payload_buffers.begin(); pbuf != payload_buffers.end(); ++pbuf)
			payload_size += buffer_size(*pbuf);
		u32(buffer_cast<packed_header*>(scratch)->payload_size, payload_size);

		buffers.insert(buffers.end(), payload_buffers.begin(), payload_buffers.end());
	}

//	assert(link.send_buffer[0] == connection::frame_network_packet);
	
	return buffers;
}
