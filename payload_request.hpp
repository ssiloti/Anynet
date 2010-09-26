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

#ifndef PAYLOAD_REQUEST_HPP
#define PAYLOAD_REQUEST_HPP

#include "packet.hpp"
#include <boost/make_shared.hpp>

class payload_request : public sendable_payload
{
public:
	virtual content_size_t content_size() const
	{
		return size;
	}

	virtual std::vector<const_buffer> serialize(packet::const_ptr_t pkt, std::size_t threshold, mutable_buffer scratch) const
	{
		packed_request* req = buffer_cast<packed_request*>(scratch);
		pkt->source().encode(req->key);
		u64(req->content_size, size);
		return std::vector<const_buffer>(1, buffer(scratch, sizeof(packed_request) + pkt->name().serialize(scratch + sizeof(packed_request))));
	}

	static std::size_t parse(packet::ptr_t pkt, const_buffer buf)
	{
		const packed_request* req = buffer_cast<const packed_request*>(buf);

		pkt->source(network_key(req->key));
		pkt->payload(boost::make_shared<payload_request>(u64(req->content_size)));
		return sizeof(packed_request) + pkt->name().parse(buf + sizeof(packed_request));
	}

	payload_request(content_size_t s) : size(s) {}

	content_size_t size;

private:
	struct packed_request
	{
		boost::uint8_t key[network_key::packed_size];
		boost::uint8_t content_size[8];
	};
};


#endif
