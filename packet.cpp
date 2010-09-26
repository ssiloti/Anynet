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

namespace
{
	struct packed_header
	{
		boost::uint8_t frame_type;
		boost::uint8_t status;
		boost::uint8_t protocol[2];
		boost::uint8_t destination[network_key::packed_size];
		boost::uint8_t payload_size[8];
	};
}

std::size_t packet::header_size()
{
	return sizeof(packed_header);
}

content_size_t packet::parse_header(const_buffer buf)
{
	const packed_header* header = buffer_cast<const packed_header*>(buf);

	content_status(content_status_t(header->status & 0x03));
	protocol(u16(header->protocol));
	destination(network_key(header->destination));

	return u64(header->payload_size);
}

std::size_t packet::serialize_header(mutable_buffer buf) const
{
	packed_header* header = buffer_cast<packed_header*>(buf);
	
	header->frame_type = connection::frame_network_packet;
	u16(header->protocol, protocol());
	header->status = content_status();
	destination().encode(header->destination);

	return sizeof(packed_header);
}

std::vector<const_buffer> packet::serialize(std::size_t threshold, mutable_buffer scratch) const
{
	DLOG(INFO) << "Sending packet dest=" << std::string(destination());

	const_ptr_t pkt(payload_->trim(shared_from_this(), threshold));

	std::vector<const_buffer> buffers;
	buffers.push_back(buffer(scratch, pkt->serialize_header(scratch)));

	content_size_t payload_size = 0;

	if (pkt->payload_.get() != NULL) {
		const std::vector<const_buffer>&
			payload_buffers = pkt->payload_->serialize(pkt, threshold, scratch + buffer_size(buffers.back()));

		for (std::vector<const_buffer>::const_iterator pbuf = payload_buffers.begin(); pbuf != payload_buffers.end(); ++pbuf)
			payload_size += buffer_size(*pbuf);

		buffers.insert(buffers.end(), payload_buffers.begin(), payload_buffers.end());
	}

	u64(buffer_cast<packed_header*>(scratch)->payload_size, payload_size);

	assert(buffer_cast<packed_header*>(scratch)->frame_type == connection::frame_network_packet);
	
	return buffers;
}
