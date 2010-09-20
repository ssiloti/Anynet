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

#ifndef PROTOCOL_HPP
#define PROTOCOL_HPP

#include <glog/logging.h>

#include "packet.hpp"
#include "connection.hpp"
#include <boost/asio/deadline_timer.hpp>
#include <boost/smart_ptr.hpp>
#include <boost/make_shared.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/range/iterator_range.hpp>
#include <boost/optional.hpp>
#include <boost/cstdint.hpp>

class local_node;

struct content_sources : public boost::enable_shared_from_this<content_sources>
{
	typedef boost::shared_ptr<content_sources> ptr_t;

	struct source
	{
		source() : stored(boost::posix_time::second_clock::universal_time()), active_request_count(0) {}
		source(ip::tcp::endpoint ep) : ep(ep), stored(boost::posix_time::second_clock::universal_time()) {}
		boost::posix_time::ptime stored;
		ip::tcp::endpoint ep;
		unsigned int active_request_count;
	};

	struct ep_cmp
	{
		bool operator()(const ip::tcp::endpoint& l, const ip::tcp::endpoint& r) const { if (l.address() == r.address()) return l.port() < r.port(); return l.address() < r.address(); }
	};

	typedef std::map<network_key, source> sources_t;

	content_sources(content_size_t s) : size(s), last_stat_source_count(0) {}

	sendable_payload::ptr_t get_payload();

	sources_t sources;
	content_size_t size;
	int last_stat_source_count; // the most recent source count which was registered with the sources_per_hunk stats
};

class payload_request : public sendable_payload
{
public:
	virtual content_size_t content_size() const
	{
		return size;
	}

	virtual std::vector<const_buffer> serialize(packet::ptr_t pkt, std::size_t threshold, mutable_buffer scratch) const
	{
		packed_request* req = buffer_cast<packed_request*>(scratch);
		pkt->source().encode(req->key);
		u64(req->content_size, size);
		return std::vector<const_buffer>(1, buffer(scratch, sizeof(packed_request)));
	}

	static std::size_t parse(packet::ptr_t pkt, const_buffer buf)
	{
		const packed_request* req = buffer_cast<const packed_request*>(buf);

		pkt->source(network_key(req->key));
		pkt->payload(boost::make_shared<payload_request>(u64(req->content_size)));
		return sizeof(packed_request);
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


class payload_failure : public sendable_payload
{
public:
	virtual content_size_t content_size() const
	{
		return sizeof(packed_error);
	}

	virtual std::vector<const_buffer> serialize(packet::ptr_t pkt, std::size_t threshold, mutable_buffer scratch) const
	{
		packed_error* error = buffer_cast<packed_error*>(scratch);
		pkt->source().encode(error->key);
		u64(error->content_size, size);
		return std::vector<const_buffer>(1, buffer(scratch, sizeof(packed_error)));
	}

	static std::size_t parse(packet::ptr_t pkt, const_buffer buf)
	{
		const packed_error* error = buffer_cast<const packed_error*>(buf);

		pkt->source(network_key(error->key));
		pkt->payload(boost::make_shared<payload_failure>(u64(error->content_size)));
		return sizeof(packed_error);
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

class signature_scheme : public boost::enable_shared_from_this<signature_scheme>
{
public:
	struct crumb
	{
		typedef std::map<network_key, boost::weak_ptr<connection> > requesters_t;

		crumb(boost::asio::io_service& ios)
			: timeout(ios)
		{ timeout.expires_from_now(boost::posix_time::seconds(5)); }

		requesters_t requesters;
		boost::asio::deadline_timer timeout;
	};

	typedef std::map<content_identifier, boost::shared_ptr<crumb> > crumbs_t;

protected:
	const static boost::posix_time::time_duration min_successor_source_age;

public:
	typedef boost::shared_ptr<signature_scheme> ptr_t;

	signature_scheme(local_node& node, signature_scheme_id p);
	virtual ~signature_scheme() {}

	signature_scheme_id id() const { return protocol_; }

	virtual void initiate_request(const content_identifier& cid, content_size_t size = 0) {}

	void receive_payload(connection::ptr_t con, packet::ptr_t pkt, std::size_t payload_size);

	// Convert request packet to general failure
	void to_content_location_failure(packet::ptr_t pkt)
	{
		pkt->to_reply(packet::content_failure, boost::make_shared<const payload_failure>(pkt->payload_as<payload_request>()->size));
	}

	// Convert general failure packet to request, used for desperation mode
	void request_from_location_failure(packet::ptr_t pkt)
	{
		pkt->to_reply(packet::content_requested, boost::make_shared<const payload_request>(pkt->payload_as<payload_failure>()->size));
	}

	void snoop_packet(packet::ptr_t pkt);
	virtual void incoming_frame(connection::ptr_t con, boost::uint8_t frame_type);

	virtual void prune_hunk(const content_identifier& id) {}

	void register_handler();

	content_sources::ptr_t get_content_sources(content_identifier id, content_size_t size);

	void drop_crumb(packet::ptr_t pkt, boost::weak_ptr<connection> c);
	void pickup_crumb(packet::ptr_t pkt);
	void pickup_crumb(const content_identifier& cid, const boost::system::error_code& error);
	boost::optional<const crumb::requesters_t&> get_crumb(packet::ptr_t pkt);

	virtual void shutdown() { shutting_down_ = true; crumbs_.clear(); }

	template <typename T>
	boost::shared_ptr<T> shared_from_this_as() { return boost::static_pointer_cast<T>(shared_from_this()); }
	template <typename T>
	boost::shared_ptr<T const> shared_from_this_as() const { return boost::static_pointer_cast<T const>(shared_from_this()); }

protected:
	typedef std::map<content_identifier, boost::array<boost::posix_time::ptime, 2> > content_requests_t;
	typedef std::map<content_identifier, content_sources::ptr_t> content_sources_t;

	virtual void receive_attached_content(connection::ptr_t con, packet::ptr_t pkt, std::size_t payload_size);

	void sources_received(connection::ptr_t con, packet::ptr_t pkt, const_buffer buf);
	void request_received(connection::ptr_t con, packet::ptr_t pkt, const_buffer buf);
	void failure_received(connection::ptr_t con, packet::ptr_t pkt, const_buffer buf);

	virtual void snoop_packet_payload(packet::ptr_t pkt) {}

	void start_vacume();

	local_node& node_;
	network_key node_id;
	content_requests_t recent_requests_;
	content_sources_t content_sources_;
	boost::asio::deadline_timer vacume_sources_;
	crumbs_t crumbs_;
	signature_scheme_id protocol_;
	bool shutting_down_;

private:
	void vacume_sources(const boost::system::error_code& error = boost::system::error_code());
};

template <typename Addr>
class payload_content_sources : public sendable_payload, public content_sources::ptr_t
{
public:
	typedef Addr address_type;

	virtual content_size_t content_size() const
	{
		return get()->size;
	}

	virtual std::vector<const_buffer> serialize(packet::ptr_t pkt, std::size_t threshold, mutable_buffer scratch) const
	{
		packed_detached_sources* s = buffer_cast<packed_detached_sources*>(scratch);
		int source_send_count = std::min(get()->sources.size(), (buffer_size(scratch) - sizeof(packed_detached_sources)) / sizeof(packed_source_address));

		pkt->source().encode(s->key);
		u64(s->size, get()->size);
		u16(s->count, source_send_count);

		// start with the last source whose id is less than the requester's, this is the best (i.e. the one he is most likely to have credit with)
		distance_iterator<content_sources::sources_t> source(get()->sources, pkt->destination());

		for (int source_idx = 0; source_idx < source_send_count; ++source_idx) {
			encode_detached_source(&s->sources[source_idx], *source);
			++source;
		}

		return std::vector<const_buffer>(1, buffer(scratch, sizeof(packed_detached_sources) + sizeof(packed_source_address) * source_send_count));
	}


	static std::size_t parse(packet::ptr_t pkt, const_buffer buf, signature_scheme& sig)
	{
		const packed_detached_sources* s = buffer_cast<const packed_detached_sources*>(buf);
		pkt->source(network_key(s->key));
		content_sources::ptr_t sources(sig.get_content_sources(pkt->content_id(), u64(s->size)));
		pkt->payload(boost::make_shared<payload_content_sources<address_type> >(sources));
		int sources_count = u16(s->count);

		for (int source_idx = 0; source_idx < sources_count; ++source_idx) {
			sources->sources.insert(decode_detached_source(&s->sources[source_idx]));
		}
		return sizeof(packed_detached_sources) + sizeof(packed_source_address) * sources_count;
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
		packed_source_address sources[];
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

		//ret.first.decode(packed_address->id);

		std::memcpy(ip_addr.data(), packed_address->address, ip_addr.size());
		ret.second.ep.address(Addr(ip_addr));
		ret.second.ep.port(u16(packed_address->port));

		return ret;
	}
};

typedef payload_content_sources<ip::address_v4> payload_content_sources_v4;
typedef payload_content_sources<ip::address_v6> payload_content_sources_v6;

#endif
