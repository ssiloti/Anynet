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

#include "protocols/user_content.hpp"
#include "node.hpp"
#include <boost/bind/protect.hpp>
#include <boost/bind.hpp>
#include <memory>

class payload_content_request : public sendable_payload
{
public:
	virtual std::size_t content_size() const
	{
		return size;
	}

	virtual std::vector<const_buffer> serialize(packet::ptr_t pkt, std::size_t threshold, mutable_buffer scratch) const
	{
		packed_request* req = buffer_cast<packed_request*>(scratch);
		pkt->source().encode(req->key);
		u32(req->content_size, size);
		return std::vector<const_buffer>(1, buffer(scratch, sizeof(packed_request)));
	}

	static std::size_t parse(packet::ptr_t pkt, const_buffer buf)
	{
		const packed_request* req = buffer_cast<const packed_request*>(buf);

		pkt->source(network_key(req->key));
		pkt->payload(new payload_content_request(u32(req->content_size)));
		return sizeof(packed_request);
	}

	payload_content_request(std::size_t s) : size(s) {}

	std::size_t size;

private:
	struct packed_request
	{
		boost::uint8_t key[network_key::packed_size];
		boost::uint8_t content_size[4];
	};
};


class payload_content_failure : public sendable_payload
{
public:
	virtual std::size_t content_size() const
	{
		return sizeof(packed_error);
	}

	virtual std::vector<const_buffer> serialize(packet::ptr_t pkt, std::size_t threshold, mutable_buffer scratch) const
	{
		packed_error* error = buffer_cast<packed_error*>(scratch);
		pkt->source().encode(error->key);
		u32(error->content_size, size);
		return std::vector<const_buffer>(1, buffer(scratch, sizeof(packed_error)));
	}

	static std::size_t parse(packet::ptr_t pkt, const_buffer buf)
	{
		const packed_error* error = buffer_cast<const packed_error*>(buf);

		pkt->source(network_key(error->key));
		pkt->payload(new payload_content_failure(u32(error->content_size)));
		return sizeof(packed_error);
	}

	payload_content_failure(std::size_t s) : size(s) {}

	std::size_t size;

private:
	struct packed_error
	{
		boost::uint8_t key[network_key::packed_size];
		boost::uint8_t content_size[4];
	};
};

template <typename Addr>
class payload_content_sources : public sendable_payload, public content_sources::ptr_t
{
public:
	typedef Addr address_type;

	virtual std::size_t content_size() const
	{
		return get()->size;
	}

	virtual std::vector<const_buffer> serialize(packet::ptr_t pkt, std::size_t threshold, mutable_buffer scratch) const
	{
		packed_detached_sources* s = buffer_cast<packed_detached_sources*>(scratch);
		int source_send_count = std::min(get()->sources.size(), (buffer_size(scratch) - sizeof(packed_detached_sources)) / sizeof(packed_source_address));

		pkt->source().encode(s->key);
		u32(s->size, get()->size);
		u16(s->count, source_send_count);

		content_sources::sources_t::const_iterator source = get()->sources.begin();
		for (int source_idx = 0; source_idx < source_send_count; ++source_idx)
			encode_detached_source(&s->sources[source_idx], (source++)->first);

		return std::vector<const_buffer>(1, buffer(scratch, sizeof(packed_detached_sources) + sizeof(packed_source_address) * (source_send_count-1)));
	}


	static std::size_t parse(packet::ptr_t pkt, const_buffer buf, user_content& protocol)
	{
		const packed_detached_sources* s = buffer_cast<const packed_detached_sources*>(buf);
		pkt->source(network_key(s->key));
		content_sources::ptr_t sources(protocol.get_content_sources(pkt->source(), u32(s->size)));
		pkt->payload(new payload_content_sources<address_type>(sources));
		int sources_count = u16(s->count);

		for (int source_idx = 0; source_idx < sources_count; ++source_idx) {
			sources->sources.insert(std::make_pair(decode_detached_source(&s->sources[source_idx]), content_sources::source()));
		}
		return sizeof(packed_detached_sources) + sizeof(packed_source_address) * (sources_count - 1);
	}

	payload_content_sources(content_sources::ptr_t s) : content_sources::ptr_t(s) {}

private:
	struct packed_source_address
	{
		boost::uint8_t address[address_type::bytes_type::static_size];
		boost::uint8_t port[2];
		boost::uint8_t rsvd[2];
	};

	struct packed_detached_sources
	{
		boost::uint8_t key[network_key::packed_size];
		boost::uint8_t size[4];
		boost::uint8_t rsvd[2];
		boost::uint8_t count[2];
		packed_source_address sources[1];
	};

	void encode_detached_source(packed_source_address* packed_address, ip::tcp::endpoint ep) const
	{
		typename address_type::bytes_type ip_addr = to<address_type>(ep.address()).to_bytes();
		std::memcpy(packed_address->address, ip_addr.data(), ip_addr.size());

		u16(packed_address->port, ep.port());
		u16(packed_address->rsvd, 0);
	}

	static ip::tcp::endpoint decode_detached_source(const packed_source_address* packed_address)
	{
		typename address_type::bytes_type ip_addr;
		ip::tcp::endpoint ep;
		std::memcpy(ip_addr.data(), packed_address->address, ip_addr.size());
		ep.address(Addr(ip_addr));

		ep.port(u16(packed_address->port));

		return ep;
	}
};

typedef payload_content_sources<ip::address_v4> payload_content_sources_v4;
typedef payload_content_sources<ip::address_v6> payload_content_sources_v6;

class payload_content_buffer : public sendable_payload
{
public:
	virtual std::size_t content_size() const
	{
		return buffer_size(payload->get());
	}

	virtual std::vector<const_buffer> serialize(boost::shared_ptr<packet> pkt, std::size_t threshold, mutable_buffer scratch) const
	{
		const_buffer buf = payload->get();
		if (buffer_size(buf) > threshold) {
			content_sources::ptr_t self_source(new content_sources(buffer_size(buf)));
			self_source->sources.insert(std::make_pair(node_.public_endpoint(), content_sources::source()));
			pkt->content_status(packet::content_detached);
			if (node_.is_v4())
				pkt->payload(new payload_content_sources_v4(self_source));
			else
				pkt->payload(new payload_content_sources_v6(self_source));
			return pkt->payload()->serialize(pkt, threshold, scratch);
		}
		else {
			return std::vector<const_buffer>(1, payload->get());
		}
	}

	payload_content_buffer(local_node& node, const_payload_buffer_ptr p) : node_(node), payload(p) {}

	const_payload_buffer_ptr payload;

private:
	local_node& node_;
};

sendable_payload* content_sources::get_payload()
{
	if (sources.empty())
		return NULL;
	else if (sources.begin()->first.address().is_v4())
		return new payload_content_sources_v4(shared_from_this());
	else
		return new payload_content_sources_v6(shared_from_this());
}

void content_request::initiate_request(protocol_t protocol, const network_key& key, local_node& node, std::size_t content_size)
{
	last_indirect_request_peer_ = node.id();
	content_size_ = content_size;

	packet::ptr_t pkt(new packet());
	pkt->protocol(protocol);
	pkt->source(node.id());
	pkt->destination(key);
	pkt->content_status(packet::content_requested);
	pkt->payload(new payload_content_request(content_size_));

	connection::ptr_t con = node.local_request(pkt, key);

	if (con)
		last_indirect_request_peer_ = con->remote_id() - 1;
}

bool content_request::snoop_packet(local_node& node, packet::ptr_t pkt)
{
	switch (pkt->content_status())
	{
	case packet::content_attached:
		for (std::vector<keyed_handler_t>::iterator handler = handlers_.begin(); handler != handlers_.end(); ++handler)
			(*handler)(pkt->payload_as<payload_content_buffer>()->payload);
		return true;
	case packet::content_detached:
		sources_ = *pkt->payload_as<content_sources::ptr_t>();
		if (direct_request_pending_ == ip::tcp::endpoint()) {
			if (!partial_content_) {
				partial_content_ = framented_content(static_cast<user_content*>(&node.get_protocol(pkt))->get_payload_buffer(sources_->size));
			}
			std::pair<std::size_t, std::size_t> range = partial_content_->next_invalid_range();
			frame_fragment::ptr_t frag(new frame_fragment(pkt->protocol(), pkt->source(), range.first, range.second));
			node.direct_request(sources_->sources.begin()->first, frag);
			direct_request_pending_ = sources_->sources.begin()->first;
		}
		return false;
	case packet::content_failure:
		if ( ( !sources_ || sources_->sources.size() == 0 ) && ( direct_request_pending_ == ip::tcp::endpoint() ) ) {

			pkt->destination(pkt->source());
			pkt->source(node.id());
			pkt->content_status(packet::content_requested);
			pkt->payload(new payload_content_request(content_size_));

			connection::ptr_t con = node.local_request(pkt, last_indirect_request_peer_);

			if (con) {
				DLOG(INFO) << "Retrying request for " << std::string(pkt->destination()) << " to " << std::string(con->remote_id()) << " with inner id " << std::string(last_indirect_request_peer_);
				last_indirect_request_peer_ = con->remote_id() - 1;
				return false;
			}
			else {
				google::FlushLogFiles(google::INFO);
				for (std::vector<keyed_handler_t>::iterator handler = handlers_.begin(); handler != handlers_.end(); ++handler)
					(*handler)(const_payload_buffer_ptr());
				return true;
			}
		}
		else if (pkt->source() == network_key(direct_request_pending_)) {
			sources_->sources.erase(direct_request_pending_);

			std::pair<std::size_t, std::size_t> range = partial_content_->next_invalid_range();
			frame_fragment::ptr_t frag(new frame_fragment(pkt->protocol(), pkt->source(), range.first, range.second));
			node.direct_request(sources_->sources.begin()->first, frag);
			direct_request_pending_ = sources_->sources.begin()->first;
			return false;
		}
	default:
		return false;
	}
}

const_payload_buffer_ptr content_request::snoop_fragment(local_node& node, ip::tcp::endpoint src, frame_fragment::ptr_t frag)
{
	if (!partial_content_) {
		// We got a fragment frame for something we haven't started a fragmented download on yet
		// just ignore it
		frag->to_request(0, 0);
		return const_payload_buffer_ptr();
	}

	direct_request_pending_ = ip::tcp::endpoint();

	switch (frag->status())
	{
	case frame_fragment::status_attached:
		{
			partial_content_->mark_valid(frag, src.address());

			const_payload_buffer_ptr payload = partial_content_->complete();

			if (payload) {
				network_key pid(payload->get());
				if (pid == frag->id())
					return payload;
				else
					partial_content_->reset();
			}
			break;
		}
	case frame_fragment::status_failed:
		if (sources_) {
			sources_->sources.erase(src);
			if (!sources_->sources.empty())
				src = sources_->sources.begin()->first;
			else
				return const_payload_buffer_ptr();
		}
		break;
	}

	std::pair<std::size_t, std::size_t> next_range(partial_content_->next_invalid_range());
	frag->to_request(next_range.first, next_range.second);
	direct_request_pending_ = src;

	return const_payload_buffer_ptr();
}

framented_content::fragment_buffer content_request::get_fragment_buffer(std::size_t offset, std::size_t size)
{
	if (partial_content_)
		return partial_content_->get_fragment_buffer(offset, size);
	else
		return framented_content::fragment_buffer(offset);
}

bool content_request::timeout(local_node& node, packet::ptr_t pkt)
{
	if (direct_request_pending_ != ip::tcp::endpoint()) {
		frame_fragment::ptr_t frag(new frame_fragment());
		snoop_fragment(node, direct_request_pending_, frag);
		if (frag->status() != frame_fragment::status_failed)
			return false;
	}

	return snoop_packet(node, pkt);
}

user_content::user_content(local_node& node, protocol_t p)
	: network_protocol(node), protocol_(p), vacume_sources_(node.io_service())
{}

void user_content::to_content_location_failure(packet::ptr_t pkt)
{
	pkt->to_reply(packet::content_failure, new payload_content_failure(pkt->payload_as<payload_content_request>()->size));
}

void user_content::request_from_location_failure(packet::ptr_t pkt)
{
	pkt->to_reply(packet::content_requested, new payload_content_request(pkt->payload_as<payload_content_failure>()->size));
}

void user_content::snoop_packet_payload(packet::ptr_t pkt)
{
	switch (pkt->content_status())
	{
	case packet::content_requested:
		{
			const_payload_buffer_ptr content = get_content(pkt->destination());

			if (content) {
				DLOG(INFO) << "Replying with content to request from " << std::string(pkt->source()) << " for " << std::string(pkt->destination());
				pkt->to_reply(packet::content_attached, new payload_content_buffer(node_, content));
				break;
			}

			content_sources_t::const_iterator detached_sources = content_sources_.find(pkt->destination());

			if (detached_sources != content_sources_.end() && detached_sources->second->sources.size() > 0) {
				DLOG(INFO) << "Respopnding with detached source to request from " << std::string(pkt->source()) << " for " << std::string(pkt->destination());
				pkt->to_reply(packet::content_detached, detached_sources->second->get_payload());
				break;
			}
			break;
		}
	case packet::content_attached:
		{
			hunk_descriptor_t hunk_desc;
			pkt->source(content_id(pkt->payload_as<payload_content_buffer>()->payload));
			if (pkt->is_direct()) {
				hunk_desc = node_.cache_local_request(id(), pkt->source(), buffer_size(pkt->payload_as<payload_content_buffer>()->payload->get()));
			}
			else if (pkt->source() == pkt->destination())
				hunk_desc = node_.cache_store(id(), pkt->source(), buffer_size(pkt->payload_as<payload_content_buffer>()->payload->get()));
			else {
				content_requests_t::iterator recent_request = recent_requests_.find(pkt->source());
				if (recent_request == recent_requests_.end() || recent_request->second[1].is_not_a_date_time())
					break;
				hunk_desc = node_.cache_remote_request(id(), pkt->source(), buffer_size(pkt->payload_as<payload_content_buffer>()->payload->get()), recent_request->second[0] - recent_request->second[1]);
			}

			if (hunk_desc != node_.not_a_hunk())
				store_content(hunk_desc, pkt->payload_as<payload_content_buffer>()->payload);
			break;
		}
	case packet::content_detached:
		{
			if ((*pkt->payload_as<content_sources::ptr_t>())->sources.size() > 1 && pkt->source() == pkt->destination()) {
				// this is a store request and we already have other sources saved
				// in this case we want to halt the store request so set the destination to ourselves
				// this will prevent the packet from being forwarded to another peer
				pkt->destination(node_.id());
			}
			break;
		}
	}

	if (pkt->content_status() == packet::content_attached) {
		// we should probably be checking in get_content_sources and not even inserting the sources
		// if we already have the content, but for now just remove it here
		content_sources_t::iterator sources = content_sources_.find(pkt->source());
		if (sources != content_sources_.end())
			content_sources_.erase(sources);
	}

	if (pkt->content_status() != packet::content_requested) {
		// see if we have an outstanding request which might be interested in this packet
		response_handlers_t::iterator keyed_handler = response_handlers_.find(pkt->source());

		if (keyed_handler != response_handlers_.end()) {
			if (keyed_handler->second->request.snoop_packet(node_, pkt)) {
			//	keyed_handler->second->timeout.cancel();
				response_handlers_.erase(keyed_handler);
			}
			else {
				// any time there's some activity on the request we reset the timeout
				keyed_handler->second->timeout.expires_from_now(boost::posix_time::seconds(5));
				keyed_handler->second->timeout.async_wait(boost::bind(&user_content::remove_response_handler,
				                                                      boost::static_pointer_cast<user_content>(shared_from_this()),
				                                                      keyed_handler->first,
				                                                      placeholders::error));
			}
		}
	}
}

void user_content::snoop_fragment(ip::tcp::endpoint src, frame_fragment::ptr_t frag)
{
	if (!frag->is_request()) {
		response_handlers_t::iterator request = response_handlers_.find(frag->id());

		if (request != response_handlers_.end()) {
			const_payload_buffer_ptr payload = request->second->request.snoop_fragment(node_, src, frag);

			if (payload) {
				packet::ptr_t pkt(new packet());
				pkt->protocol(id());
				pkt->content_status(packet::content_attached);
				pkt->mark_direct();
				pkt->destination(node_.id());
				pkt->payload(new payload_content_buffer(node_, payload));
				snoop_packet(pkt);
				return;
			}
			else if (frag->status() == frame_fragment::status_failed) {
				packet::ptr_t pkt(new packet());
				pkt->protocol(id());
				pkt->content_status(packet::content_failure);
				pkt->source(frag->id());
				pkt->destination(node_.id());
				pkt->payload(new payload_content_failure(0));
				if (request->second->request.snoop_packet(node_, pkt)) {
				//	request->second->timeout.cancel();
					response_handlers_.erase(request);
					return;
				}
			}

			// any time there's some activity on the request we reset the timeout
			request->second->timeout.expires_from_now(boost::posix_time::seconds(5));
			request->second->timeout.async_wait(boost::bind(&user_content::remove_response_handler,
			                                                boost::static_pointer_cast<user_content>(shared_from_this()),
			                                                request->first,
			                                                placeholders::error));
		}
	}
	else {
		const_payload_buffer_ptr content = get_content(frag->id());

		if (content)
			frag->to_reply(content);
		else
			frag->to_reply();

		node_.direct_request(src, frag);
	}
}

void user_content::receive_payload(connection::ptr_t con, packet::ptr_t pkt, std::size_t payload_size)
{
	switch (pkt->content_status())
	{
	case packet::content_attached:
		{
			if (payload_size == 0) {
				packet::ptr_t p;
				node_.packet_received(con, p);
			}
			else {
				payload_buffer_ptr payload_buffer(get_payload_buffer(payload_size));
				pkt->payload(new payload_content_buffer(node_, payload_buffer));
				con->receive_payload(std::vector<mutable_buffer>(1, payload_buffer->get()), boost::protect(boost::bind(&user_content::content_received, this, con, pkt)));
			}
			break;
		}
	case packet::content_detached:
		{
			if (payload_size == 0) {
				packet::ptr_t p;
				node_.packet_received(con, p);
			}
			else {
				con->receive_payload(payload_size, boost::protect(boost::bind(&user_content::sources_received, this, con, pkt, _1)));
			}
			break;
		}
	case packet::content_requested:
		{
			if (payload_size == 0) {
				packet::ptr_t p;
				node_.packet_received(con, p);
			}
			else {
				con->receive_payload(payload_size, boost::protect(boost::bind(&user_content::request_received, this, con, pkt, _1)));
			}
			break;
		}
	case packet::content_failure:
		{
			if (payload_size == 0) {
				packet::ptr_t p;
				node_.packet_received(con, p);
			}
			else {
				con->receive_payload(payload_size, boost::protect(boost::bind(&user_content::failure_received, this, con, pkt, _1)));
			}
			break;
		}
	}
}

void user_content::content_received(connection::ptr_t con, packet::ptr_t pkt)
{
	node_.packet_received(con, pkt);
}

void user_content::sources_received(connection::ptr_t con, packet::ptr_t pkt, const_buffer buf)
{
	if (con->remote_endpoint().address().is_v4())
		payload_content_sources_v4::parse(pkt, buf, *this);
	else
		payload_content_sources_v6::parse(pkt, buf, *this);
	node_.packet_received(con, pkt);
}

void user_content::request_received(connection::ptr_t con, packet::ptr_t pkt, const_buffer buf)
{
	payload_content_request::parse(pkt, buf);
	node_.packet_received(con, pkt);
}

void user_content::failure_received(connection::ptr_t con, packet::ptr_t pkt, const_buffer buf)
{
	payload_content_failure::parse(pkt, buf);
	node_.packet_received(con, pkt);
}

void user_content::incoming_fragment(connection::ptr_t con, frame_fragment::ptr_t frag, std::size_t payload_size)
{
	if (payload_size) {
		framented_content::fragment_buffer payload = get_fragment_buffer(frag);

	#if 0
		if (buffer_size(payload.buf) == 0) {
			node_.receive_failure(con);
			return;
		}
	#endif

		assert(payload.offset >= frag->offset());
		assert(buffer_size(payload.buf) <= frag->size());

		std::vector<mutable_buffer> buffers;

		std::size_t head_excess = payload.offset - frag->offset();

		head_excess -= con->discard_payload(head_excess);

		if (head_excess) {
			boost::shared_ptr<heap_buffer> head_pad(new heap_buffer(head_excess));
			frag->attach_padding(head_pad);
			buffers.push_back(head_pad->get());
		}

		if (buffer_size(payload.buf))
			buffers.push_back(payload.buf);

		frag->payload(payload.content);

		std::size_t tail_excess = frag->size() - buffer_size(payload.buf) - (payload.offset - frag->offset());

	//	tail_excess -= con->discard_payload(tail_excess);

		if (tail_excess) {
			boost::shared_ptr<heap_buffer> tail_pad(new heap_buffer(tail_excess));
			frag->attach_padding(tail_pad);
			buffers.push_back(tail_pad->get());
		}

		con->receive_payload(buffers,
							 boost::protect(boost::bind(&user_content::content_fragment_received,
														boost::static_pointer_cast<user_content>(shared_from_this()),
														con,
														frag)));
	}
	else {
		snoop_fragment(con->remote_endpoint(), frag);
	}
}

void user_content::content_fragment_received(connection::ptr_t con, frame_fragment::ptr_t frag)
{
	frag->clear_padding();
	snoop_fragment(con->remote_endpoint(), frag);
}

void user_content::start_vacume()
{
	vacume_sources_.expires_from_now(boost::posix_time::minutes(1));
	vacume_sources_.async_wait(boost::bind(&user_content::vacume_sources,
	                                       boost::static_pointer_cast<user_content>(shared_from_this()),
										   _1)); // TODO: Using boost::asio::placeholders::error here results in
	                                             // a null pointer dereference!? Need to understand what the hell is
	                                             // up with that
}

content_sources::ptr_t user_content::get_content_sources(network_key id, std::size_t size)
{
	std::pair<content_sources_t::iterator, bool> found_sources = content_sources_.insert( std::make_pair( id, content_sources::ptr_t() ) );

	if (found_sources.second)
		found_sources.first->second.reset(new content_sources(size));

	return found_sources.first->second;
}

framented_content::fragment_buffer user_content::get_fragment_buffer(frame_fragment::ptr_t frag)
{
	response_handlers_t::iterator request = response_handlers_.find(frag->id());

	if (request != response_handlers_.end())
		return request->second->request.get_fragment_buffer(frag->offset(), frag->size());
	else
		return framented_content::fragment_buffer(frag->offset());
}

void user_content::new_content_request(const network_key& key, std::size_t content_size, const content_request::keyed_handler_t& handler)
{
	std::pair<response_handlers_t::iterator, bool> rh = response_handlers_.insert(std::make_pair(key, boost::shared_ptr<response_handler>()));

	if (rh.second) {
		rh.first->second.reset(new response_handler(node_.io_service()));
		rh.first->second->timeout.async_wait(boost::bind(&user_content::remove_response_handler,
		                                                 boost::static_pointer_cast<user_content>(shared_from_this()),
		                                                 rh.first->first,
		                                                 placeholders::error));
	}

	if (handler)
		rh.first->second->request.add_handler(handler);

	if (rh.second)
		rh.first->second->request.initiate_request(id(), key, node_, content_size);
}

void user_content::new_content_store(const_payload_buffer_ptr hunk)
{
	network_key key(hunk->get());
	packet::ptr_t pkt(new packet());
	pkt->destination(key);
	pkt->source(key);
	pkt->content_status(packet::content_attached);
	pkt->protocol(id());
	pkt->payload(new payload_content_buffer(node_, hunk));
	node_.local_request(pkt);
}

void user_content::remove_response_handler(network_key key, const boost::system::error_code& error)
{
	if (!error) {
		DLOG(INFO) << std::string(node_.id()) << ": Removing response handler " << std::string(key);
		response_handlers_t::iterator iter = response_handlers_.find(key);
		if (iter != response_handlers_.end()) {
			google::FlushLogFiles(google::INFO);
			packet::ptr_t pkt(new packet());
			pkt->protocol(id());
			pkt->content_status(packet::content_failure);
			pkt->source(key);
			pkt->destination(node_.id());
			pkt->payload(new payload_content_failure(0));
			if (iter->second->request.timeout(node_, pkt))
				// request has nothing more to do, put him out of his misery
				response_handlers_.erase(iter);
			else {
				// we had a timeout but the request still has sources to try, reset the timer
				iter->second->timeout.expires_from_now(boost::posix_time::seconds(5));
				iter->second->timeout.async_wait(boost::bind(&user_content::remove_response_handler,
				                                             boost::static_pointer_cast<user_content>(shared_from_this()),
				                                             iter->first,
				                                             placeholders::error));
			}
		}
	}
}

void user_content::vacume_sources(const boost::system::error_code& error)
{
	if (!error && !shutting_down_) {
		boost::posix_time::ptime now = boost::posix_time::second_clock::universal_time();
		boost::posix_time::time_duration age_cap = node_.base_hunk_lifetime();

		for (content_sources_t::iterator content = content_sources_.begin(); content != content_sources_.end();) {
			bool successor = node_.closer_peers(content->first) == 0;
			for (content_sources::sources_t::iterator source = content->second->sources.begin(); source != content->second->sources.end();) {
				boost::posix_time::time_duration age = now - source->second.stored;
				if ( (age < age_cap) || (successor && age < min_successor_source_age) ) {
					++source;
				}
				else {
					content_sources::sources_t::iterator next = source;
					++next;
					content->second->sources.erase(source);
					source = next;
				}
			}

			if (content->second->sources.size() > 0) {
				++content;
			}
			else {
				content_sources_t::iterator next = content;
				++next;
				content_sources_.erase(content);
				content = next;
			}
		}

		vacume_sources_.expires_from_now(boost::posix_time::minutes(1));
		vacume_sources_.async_wait(boost::bind(&user_content::vacume_sources,
		                                       boost::static_pointer_cast<user_content>(shared_from_this()),
		                                       placeholders::error));
	}
	else if (!error)
		DLOG(INFO) << std::string(node_.id()) << ": Vacuming sources";
}
