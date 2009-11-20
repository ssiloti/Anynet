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

template <typename Addr>
struct packed_source_address
{
	boost::uint8_t address[Addr::bytes_type::static_size];
	boost::uint8_t port[2];
	boost::uint8_t rsvd[2];
};

template <typename Addr>
struct packed_detached_sources
{
	boost::uint8_t key[network_key::packed_size];
	boost::uint8_t size[4];
	boost::uint8_t rsvd[2];
	boost::uint8_t count[2];
	packed_source_address<Addr> sources[1];
};

template <typename Addr>
struct packed_content_detached
{
	packed_header header;
	packed_detached_sources<Addr> detached_sources;
};

struct packed_request
{
	boost::uint8_t key[network_key::packed_size];
	boost::uint8_t content_size[4];
};

struct packed_content_requested
{
	packed_header header;
	packed_request request;
};

struct packed_error
{
	boost::uint8_t key[network_key::packed_size];
	boost::uint8_t error_code;
};

struct packed_content_failure
{
	packed_header header;
	packed_error error;
};

std::size_t packet::header_size()
{
	return sizeof(packed_header);
}

std::size_t packet::parse_header(const boost::uint8_t* h)
{
	const packed_header* header = reinterpret_cast<const packed_header*>(h);

	content_status(content_status_t(header->protocol >> 6));
	protocol(header->protocol & 0x3F);
	destination(network_key(header->destination));
	return u32(header->payload_size);
}

std::size_t packet::serialize_header(boost::uint8_t* buf)
{
	packed_header* header = reinterpret_cast<packed_header*>(buf);
	
	header->frame_type = connection::frame_network_packet;
	header->protocol = protocol();
	header->protocol |= content_status() << 6;
	destination().encode(header->destination);

	boost::uint32_t payload_size;
	std::size_t buffer_valid_count;

	if (content_status() == content_attached) {
		payload_size = buffer_size(payload()->get());
		buffer_valid_count = sizeof(packed_header);
	}
	else if (content_status() == content_requested) {
		packed_content_requested* request_header = reinterpret_cast<packed_content_requested*>(buf);
		source().encode(request_header->request.key);
		u32(request_header->request.content_size, boost::get<boost::uint32_t>(payload_));
		payload_size = sizeof(packed_request);
		buffer_valid_count = sizeof(packed_content_requested);
	}
	else if (content_status() == content_detached) {
		buffer_valid_count = serialize_sources(buf);
		payload_size = buffer_valid_count - sizeof(packed_header);
	}
	else if (content_status() == content_failure) {
		packed_content_failure* error_header = reinterpret_cast<packed_content_failure*>(buf);
		source().encode(error_header->error.key);
		error_header->error.error_code = boost::get<error_code_t>(payload_);
		payload_size = sizeof(packed_error);
		buffer_valid_count = sizeof(packed_content_failure);
	}
	else {
		payload_size = 0;
		buffer_valid_count = sizeof(packed_header);
	}

	u32(header->payload_size, payload_size);

	return buffer_valid_count;
}

template <typename Addr>
void encode_detached_source(packed_source_address<Addr>* packed_address, ip::tcp::endpoint ep)
{
	typename Addr::bytes_type ip_addr = to<Addr>(ep.address()).to_bytes();
	std::memcpy(packed_address->address, ip_addr.data(), ip_addr.size());

	u16(packed_address->port, ep.port());
	u16(packed_address->rsvd, 0);
}

template<typename Addr>
std::size_t do_serialize_sources(boost::uint8_t* buf, const network_key& key, const content_sources& sources)
{
	packed_content_detached<Addr>* s = reinterpret_cast<packed_content_detached<Addr>*>(buf);
	int source_send_count = std::min(sources.sources.size(), (net_link::sr_buffer_size - sizeof(packed_content_detached<Addr>)) / sizeof(packed_source_address<Addr>));

	key.encode(s->detached_sources.key);
	u32(s->detached_sources.size, sources.size);
	u16(s->detached_sources.count, source_send_count);

	content_sources::sources_t::const_iterator source = sources.sources.begin();
	for (int source_idx = 0; source_idx < source_send_count; ++source_idx)
		encode_detached_source<Addr>(&s->detached_sources.sources[source_idx], (source++)->first);

	return sizeof(packed_content_detached<Addr>) + sizeof(packed_source_address<Addr>) * (source_send_count-1);
}

std::size_t packet::serialize_sources(boost::uint8_t* buf)
{
	if (sources()->sources.begin()->first.address().is_v4())
		return do_serialize_sources<ip::address_v4>(buf, source(), *sources());
	else
		return do_serialize_sources<ip::address_v6>(buf, source(), *sources());
}

template <typename Addr>
ip::tcp::endpoint decode_detached_source(packed_source_address<Addr>* packed_address)
{
	typename Addr::bytes_type ip_addr;
	ip::tcp::endpoint ep;
	std::memcpy(ip_addr.data(), packed_address->address, ip_addr.size());
	ep.address(Addr(ip_addr));

	ep.port(u16(packed_address->port));

	return ep;
}

template<typename Addr>
std::size_t do_parse_detached_sources(net_link& link, const network_key& dest, content_sources::ptr_t sources)
{
	packed_detached_sources<Addr>* h = reinterpret_cast<packed_detached_sources<Addr>*>(link.receive_buffer.data());
	int sources_count = u16(h->count);

	for (int source_idx = 0; source_idx < sources_count; ++source_idx) {
		sources->sources.insert(std::make_pair(decode_detached_source<Addr>(&h->sources[source_idx]), content_sources::source()));
	}
	return sizeof(packed_detached_sources<Addr>) + sizeof(packed_source_address<Addr>) * (sources_count - 1);
}

std::size_t packet::parse_detached_sources(net_link& link, content_sources::ptr_t sources)
{
	payload_ = sources;
	if (link.socket.remote_endpoint().address().is_v4())
		return do_parse_detached_sources<ip::address_v4>(link, destination(), sources);
	else
		return do_parse_detached_sources<ip::address_v6>(link, destination(), sources);
}

void packet::parse_request(net_link& link)
{
	packed_request* req = reinterpret_cast<packed_request*>(link.receive_buffer.data());

	source(network_key(req->key));
	payload_ = u32(req->content_size);
}

void packet::parse_failure(net_link& link)
{
	packed_error* error = reinterpret_cast<packed_error*>(link.receive_buffer.data());

	source(network_key(error->key));
	payload_ = error_code_t(error->error_code);
}

std::size_t packet::detached_content_size(net_link& link)
{
	if (link.socket.remote_endpoint().address().is_v4())
		return u32(reinterpret_cast<packed_detached_sources<ip::address_v4>*>(link.receive_buffer.data())->size);
	else
		return u32(reinterpret_cast<packed_detached_sources<ip::address_v6>*>(link.receive_buffer.data())->size);
}

std::vector<const_buffer> packet::serialize(mutable_buffer scratch)
{
	DLOG(INFO) << "Sending packet dest=" << std::string(destination());

	std::vector<const_buffer> buffers;
	buffers.push_back(buffer(scratch, serialize_header(buffer_cast<boost::uint8_t*>(scratch))));

	if (payload_.type() == typeid(const_payload_buffer_ptr)) {
		if (payload())
			buffers.push_back(payload()->get());
	}

//	assert(link.send_buffer[0] == connection::frame_network_packet);
	
	return buffers;
}
