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

#ifndef PAYLOAD_FAILURE_HPP
#define PAYLOAD_FAILURE_HPP

#include "packet.hpp"
#include <boost/make_shared.hpp>

class payload_failure : public sendable_payload
{
public:
	virtual content_size_t content_size() const
	{
		return sizeof(packed_error);
	}

	virtual std::vector<const_buffer> serialize(packet::const_ptr_t pkt, std::size_t threshold, mutable_buffer scratch) const
	{
		packed_error* error = buffer_cast<packed_error*>(scratch);
		pkt->source().encode(error->key);
		u64(error->content_size, size);
		return std::vector<const_buffer>(1, buffer(scratch, sizeof(packed_error) + pkt->name().serialize(scratch + sizeof(packed_error))));
	}

	static std::size_t parse(packet::ptr_t pkt, const_buffer buf)
	{
		const packed_error* error = buffer_cast<const packed_error*>(buf);

		pkt->source(network_key(error->key));
		pkt->payload(boost::make_shared<payload_failure>(u64(error->content_size)));
		return sizeof(packed_error) + pkt->name().parse(buf + sizeof(packed_error));
	}

	payload_failure(content_size_t s) : size(s) {}

	content_size_t size;

private:
	struct packed_error
	{
		boost::uint8_t key[network_key::packed_size];
		boost::uint8_t content_size[8];
	};
};

#endif
