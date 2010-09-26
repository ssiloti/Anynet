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

#ifndef PAYLOAD_SOURCES_HPP
#define PAYLOAD_SOURCES_HPP

#include "protocol.hpp"
#include "content_sources.hpp"
#include "packet.hpp"

template <typename Addr>
class payload_content_sources : public sendable_payload, public content_sources::ptr_t
{
public:
	typedef Addr address_type;

	virtual content_size_t content_size() const
	{
		return get()->size;
	}

	virtual std::vector<const_buffer> serialize(packet::const_ptr_t pkt, std::size_t threshold, mutable_buffer scratch) const
	{
		packed_detached_sources* s = buffer_cast<packed_detached_sources*>(scratch);
		int source_send_count = std::min(get()->sources.size(), (buffer_size(scratch) - sizeof(packed_detached_sources)) / sizeof(packed_source_address));
		std::size_t name_size = pkt->name().serialize(scratch + sizeof(packed_detached_sources));

		pkt->source().encode(s->key);
		u64(s->size, get()->size);
		u16(s->rsvd, 0);
		u16(s->count, source_send_count);

		// start with the last source whose id is less than the requester's, this is the best (i.e. the one he is most likely to have credit with)
		distance_iterator<content_sources::sources_t> source(get()->sources, pkt->destination());
		packed_source_address* packed_source = buffer_cast<packed_source_address*>(scratch + sizeof(packed_detached_sources) + name_size);
		packed_source_address* packed_sources_end = packed_source + source_send_count;

		for (; packed_source < packed_sources_end; ++packed_source, ++source)
			encode_detached_source(packed_source, *source);

		return std::vector<const_buffer>(1, buffer(scratch,
		                                    sizeof(packed_detached_sources)
		                                    + sizeof(packed_source_address) * source_send_count
		                                    + name_size));
	}

	static std::size_t parse(packet::ptr_t pkt, const_buffer buf, network_protocol& protocol)
	{
		const packed_detached_sources* s = buffer_cast<const packed_detached_sources*>(buf);
		pkt->source(network_key(s->key));
		std::size_t name_size = pkt->name().parse(buf + sizeof(packed_detached_sources));
		content_sources::ptr_t sources(protocol.get_content_sources(pkt->content_id(), u64(s->size)));
		pkt->payload(boost::make_shared<payload_content_sources<address_type> >(sources));
		int sources_count = u16(s->count);

		const packed_source_address* packed_source = buffer_cast<const packed_source_address*>(buf + sizeof(packed_detached_sources) + name_size);
		const packed_source_address* packed_sources_end = packed_source + sources_count;

		for (; packed_source < packed_sources_end; ++packed_source)
			sources->sources.insert(decode_detached_source(packed_source));

		return sizeof(packed_detached_sources) + name_size + sizeof(packed_source_address) * sources_count;
	}

	payload_content_sources(content_sources::ptr_t s) : content_sources::ptr_t(s) {}

private:
	struct packed_source_address
	{
		boost::uint8_t address[address_type::bytes_type::static_size];
		boost::uint8_t port[2];
		boost::uint8_t rsvd[2];
		boost::uint8_t id[network_key::packed_size];
	};

	struct packed_detached_sources
	{
		boost::uint8_t key[network_key::packed_size];
		boost::uint8_t size[8];
		boost::uint8_t rsvd[2];
		boost::uint8_t count[2];
	};

	void encode_detached_source(packed_source_address* packed_address, const content_sources::sources_t::value_type& src) const
	{
		typename address_type::bytes_type ip_addr = to<address_type>(src.second.ep.address()).to_bytes();
		std::memcpy(packed_address->address, ip_addr.data(), ip_addr.size());

		src.first.encode(packed_address->id);

		u16(packed_address->port, src.second.ep.port());
		u16(packed_address->rsvd, 0);
	}

	static content_sources::sources_t::value_type decode_detached_source(const packed_source_address* packed_address)
	{
		typename address_type::bytes_type ip_addr;
		content_sources::sources_t::value_type ret(packed_address->id, content_sources::sources_t::mapped_type());

		// TODO: Fix this
	//	ret.first.decode(packed_address->id);

		std::memcpy(ip_addr.data(), packed_address->address, ip_addr.size());
		ret.second.ep.address(Addr(ip_addr));
		ret.second.ep.port(u16(packed_address->port));

		return ret;
	}
};

typedef payload_content_sources<ip::address_v4> payload_content_sources_v4;
typedef payload_content_sources<ip::address_v6> payload_content_sources_v6;

#endif
