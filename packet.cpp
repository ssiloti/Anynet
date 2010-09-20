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
	boost::uint8_t status_name_components;
	boost::uint8_t sig_scheme[2];
	boost::uint8_t destination[network_key::packed_size];
	boost::uint8_t payload_size[8];
};

std::size_t packet::header_size()
{
	return sizeof(packed_header);
}

std::pair<content_size_t, unsigned> packet::parse_header(const_buffer buf)
{
	const packed_header* header = buffer_cast<const packed_header*>(buf);

	content_status(content_status_t((header->status_name_components & 0xC0) >> 6));
	sig(u16(header->sig_scheme));
	destination(network_key(header->destination));

	if (content_status() == content_attached)
		assert(u64(header->payload_size) < 24);
	else {
		google::FlushLogFiles(google::INFO);
		assert(u64(header->payload_size) < 256);
	}

	return std::make_pair(u64(header->payload_size), header->status_name_components & 0x3F);
}

std::size_t packet::serialize_header(mutable_buffer buf)
{
	packed_header* header = buffer_cast<packed_header*>(buf);
	
	header->frame_type = connection::frame_network_packet;
	u16(header->sig_scheme, sig());
	header->status_name_components = (content_status() << 6) | name().component_count();
	destination().encode(header->destination);

	return sizeof(packed_header) + name().serialize(buf + sizeof(packed_header), false);
}

std::vector<const_buffer> packet::serialize(std::size_t threshold,mutable_buffer scratch)
{
	DLOG(INFO) << "Sending packet dest=" << std::string(destination());

	std::vector<const_buffer> buffers;
	buffers.push_back(buffer(scratch, serialize_header(scratch)));

	content_size_t payload_size = 0;
	packed_header* h = buffer_cast<packed_header*>(scratch);

	if (payload_.get() != NULL) {
		const std::vector<const_buffer>& payload_buffers = payload_->serialize(shared_from_this(), threshold, scratch + buffer_size(buffers.back()));

		for (std::vector<const_buffer>::const_iterator pbuf = payload_buffers.begin(); pbuf != payload_buffers.end(); ++pbuf)
			payload_size += buffer_size(*pbuf);
		// HACK: The payload may have decided to change our status, update it here
		h->status_name_components = (content_status() << 6) | name().component_count();
		buffers.insert(buffers.end(), payload_buffers.begin(), payload_buffers.end());
	}

	u64(h->payload_size, payload_size);

	assert(buffer_cast<packed_header*>(scratch)->frame_type == connection::frame_network_packet);
	google::FlushLogFiles(google::INFO);
	assert(payload_size < 256);
	
	return buffers;
}
