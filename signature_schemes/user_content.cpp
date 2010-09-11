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

#include "signature_schemes/user_content.hpp"
#include "node.hpp"
#include <boost/bind/protect.hpp>
#include <boost/bind.hpp>
#include <boost/make_shared.hpp>
#include <memory>

class payload_content_buffer : public sendable_payload
{
public:
	virtual content_size_t content_size() const
	{
		return buffer_size(payload->get());
	}

	virtual std::vector<const_buffer> serialize(boost::shared_ptr<packet> pkt, std::size_t threshold, mutable_buffer scratch) const
	{
		const_buffer buf = payload->get();
		if (buffer_size(buf) > threshold) {
			content_sources::ptr_t self_source(new content_sources(buffer_size(buf)));
			self_source->sources.insert(std::make_pair(node_.id(), content_sources::source(node_.public_endpoint())));
			pkt->content_status(packet::content_detached);
			if (node_.is_v4())
				pkt->payload(boost::make_shared<payload_content_sources_v4>(self_source));
			else
				pkt->payload(boost::make_shared<payload_content_sources_v6>(self_source));
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

void user_content_request::initiate_request(signature_scheme_id sig, const content_identifier& key, local_node& node, content_size_t content_size)
{
	last_indirect_request_peer_ = node.id();
	content_size_ = content_size;

	packet::ptr_t pkt(new packet());
	pkt->sig(sig);
	pkt->source(node.id());
	pkt->destination(key.publisher);
	pkt->name(key.name);
	pkt->content_status(packet::content_requested);
	pkt->payload(boost::make_shared<payload_request>(content_size_));

	connection::ptr_t con = node.local_request(pkt, key.publisher);

	if (con)
		last_indirect_request_peer_ = con->remote_id() - 1;
}

bool user_content_request::snoop_packet(local_node& node, packet::ptr_t pkt)
{
	switch (pkt->content_status())
	{
	case packet::content_attached:
		for (std::vector<keyed_handler_t>::iterator handler = handlers_.begin(); handler != handlers_.end(); ++handler)
			(*handler)(pkt->payload_as<payload_content_buffer>()->payload);
		return true;
	case packet::content_detached:
		sources_ = *pkt->payload_as<content_sources::ptr_t>();
		if (!direct_request_pending_) {
			if (!partial_content_) {
				// For now we can't download content which is larger than size_t
				// this would require modifications in the hunk store to do partial mapping
				if (sources_->size > std::numeric_limits<std::size_t>::max()) {
					for (std::vector<keyed_handler_t>::iterator handler = handlers_.begin(); handler != handlers_.end(); ++handler)
						(*handler)(const_payload_buffer_ptr());
					return true;
				}
				partial_content_ = framented_content(static_cast<user_content*>(&node.get_protocol(pkt))->get_payload_buffer(std::size_t(sources_->size)));
			}
			std::pair<std::size_t, std::size_t> range = partial_content_->next_invalid_range();
			frame_fragment::ptr_t frag(new frame_fragment(pkt->sig(), pkt->content_id(), range.first, range.second));
			node.direct_request(sources_->sources.begin()->second.ep, frag);
			++sources_->sources.begin()->second.active_request_count;
			direct_request_pending_ = true;
			direct_request_peer_ = sources_->sources.begin()->first;
		}
		return false;
	case packet::content_failure:
		if (pkt->source() == direct_request_peer_) {
			sources_->sources.erase(direct_request_peer_);
			direct_request_pending_ = false;
		}

		if ( !direct_request_pending_ ) {


			pkt->destination(pkt->source());
			pkt->source(node.id());
			pkt->content_status(packet::content_requested);
			pkt->payload(boost::make_shared<payload_request>(content_size_));

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
		else {
			return false;
		}
	default:
		return false;
	}
}

const_payload_buffer_ptr user_content_request::snoop_fragment(local_node& node, const network_key& src, frame_fragment::ptr_t frag)
{
	if (!partial_content_) {
		// We got a fragment frame for something we haven't started a fragmented download on yet
		// just ignore it
		frag->to_request(0, 0);
		return const_payload_buffer_ptr();
	}

	content_sources::sources_t::iterator content_source = sources_->sources.find(src);

	direct_request_pending_ = false;
	--content_source->second.active_request_count;

	switch (frag->status())
	{
	case frame_fragment::status_attached:
		{
			partial_content_->mark_valid(frag, content_source->second.ep.address());

			const_payload_buffer_ptr payload = partial_content_->complete();

			if (payload) {
				// TODO: Call out to virtual validate function instead of enforcing pid == hash of content
				network_key pid(payload->get());
				if (pid == frag->id().publisher)
					return payload;
				else
					partial_content_->reset();
			}
			break;
		}
	case frame_fragment::status_failed:
		if (sources_) {
			sources_->sources.erase(content_source);
			if (!sources_->sources.empty()) {
				content_source = sources_->sources.begin();
			}
			else
				return const_payload_buffer_ptr();
		}
		break;
	}

	std::pair<std::size_t, std::size_t> next_range(partial_content_->next_invalid_range());
	frag->to_request(next_range.first, next_range.second);
	node.direct_request(content_source->second.ep, frag);
	++content_source->second.active_request_count;
	direct_request_pending_ = true;
	direct_request_peer_ = content_source->first;

	return const_payload_buffer_ptr();
}

framented_content::fragment_buffer user_content_request::get_fragment_buffer(std::size_t offset, std::size_t size)
{
	if (partial_content_)
		return partial_content_->get_fragment_buffer(offset, size);
	else
		return framented_content::fragment_buffer(offset);
}

bool user_content_request::timeout(local_node& node, packet::ptr_t pkt)
{
	if (direct_request_pending_) {
		frame_fragment::ptr_t frag(new frame_fragment());
		snoop_fragment(node, direct_request_peer_, frag);
		if (frag->status() != frame_fragment::status_failed)
			return false;
	}

	return snoop_packet(node, pkt);
}

user_content::user_content(local_node& node, signature_scheme_id p)
	: fragmented_protocol(node, p)
{}

void user_content::to_content_location_failure(packet::ptr_t pkt)
{
	pkt->to_reply(packet::content_failure, boost::make_shared<payload_failure>(pkt->payload_as<payload_request>()->size));
}

void user_content::request_from_location_failure(packet::ptr_t pkt)
{
	pkt->to_reply(packet::content_requested, boost::make_shared<payload_request>(pkt->payload_as<payload_failure>()->size));
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
				pkt->to_reply(packet::content_attached, boost::make_shared<payload_content_buffer>(boost::ref(node_), content));
				break;
			}

			content_sources_t::const_iterator detached_sources = content_sources_.find(pkt->content_id());

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
			content_identifier cid(content_id(pkt->payload_as<payload_content_buffer>()->payload));
			pkt->source(cid.publisher);
			pkt->name(cid.name);
			if (pkt->is_direct()) {
				hunk_desc = node_.cache_local_request(id(), pkt->source(), buffer_size(pkt->payload_as<payload_content_buffer>()->payload->get()));
			}
			else if (pkt->source() == pkt->destination())
				hunk_desc = node_.cache_store(id(), pkt->source(), buffer_size(pkt->payload_as<payload_content_buffer>()->payload->get()));
			else {
				content_requests_t::iterator recent_request = recent_requests_.find(pkt->content_id());
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
		content_sources_t::iterator sources = content_sources_.find(pkt->content_id());
		if (sources != content_sources_.end())
			content_sources_.erase(sources);
	}

	if (pkt->content_status() != packet::content_requested) {
		// see if we have an outstanding request which might be interested in this packet
		response_handlers_t::iterator keyed_handler = response_handlers_.find(pkt->content_id());

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

void user_content::snoop_fragment(const network_key& src, frame_fragment::ptr_t frag)
{
	if (!frag->is_request()) {
		response_handlers_t::iterator request = response_handlers_.find(frag->id());

		if (request != response_handlers_.end()) {
			const_payload_buffer_ptr payload = request->second->request.snoop_fragment(node_, src, frag);

			if (payload) {
				packet::ptr_t pkt(new packet());
				pkt->sig(id());
				pkt->content_status(packet::content_attached);
				pkt->mark_direct();
				pkt->destination(node_.id());
				pkt->name(frag->id().name);
				pkt->payload(boost::make_shared<payload_content_buffer>(boost::ref(node_), payload));
				snoop_packet(pkt);
				return;
			}
			else if (frag->status() == frame_fragment::status_failed) {
				packet::ptr_t pkt(new packet());
				pkt->sig(id());
				pkt->content_status(packet::content_failure);
				pkt->source(frag->id().publisher);
				pkt->name(frag->id().name);
				pkt->destination(node_.id());
				pkt->payload(boost::make_shared<payload_failure>(0));
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
	}
}

void user_content::receive_attached_content(connection::ptr_t con, packet::ptr_t pkt, std::size_t payload_size)
{
	payload_buffer_ptr payload_buffer(get_payload_buffer(payload_size));
	pkt->payload(boost::make_shared<payload_content_buffer>(boost::ref(node_), payload_buffer));
	con->receive_payload(std::vector<mutable_buffer>(1, payload_buffer->get()), boost::protect(boost::bind(&user_content::content_received, this, con, pkt)));
}

void user_content::content_received(connection::ptr_t con, packet::ptr_t pkt)
{
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
		snoop_fragment(con->remote_id(), frag);
	}
}

void user_content::content_fragment_received(connection::ptr_t con, frame_fragment::ptr_t frag)
{
	frag->clear_padding();
	snoop_fragment(con->remote_id(), frag);
}

framented_content::fragment_buffer user_content::get_fragment_buffer(frame_fragment::ptr_t frag)
{
	response_handlers_t::iterator request = response_handlers_.find(frag->id());

	if (request != response_handlers_.end())
		return request->second->request.get_fragment_buffer(frag->offset(), frag->size());
	else
		return framented_content::fragment_buffer(frag->offset());
}

void user_content::new_content_request(const content_identifier& key, content_size_t content_size, const user_content_request::keyed_handler_t& handler)
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

void user_content::new_content_store(content_identifier cid, const_payload_buffer_ptr hunk)
{
	DLOG(INFO) << "New store request for cid " << std::string(cid.publisher);
	packet::ptr_t pkt(new packet());
	pkt->destination(cid.publisher);
	pkt->source(cid.publisher);
	pkt->name(cid.name);
	pkt->content_status(packet::content_attached);
	pkt->sig(id());
	pkt->payload(boost::make_shared<payload_content_buffer>(boost::ref(node_), hunk));
	node_.local_request(pkt);
}

void user_content::remove_response_handler(content_identifier key, const boost::system::error_code& error)
{
	if (!error) {
		DLOG(INFO) << std::string(node_.id()) << ": Removing response handler " << std::string(key.publisher);
		response_handlers_t::iterator iter = response_handlers_.find(key);
		if (iter != response_handlers_.end()) {
			google::FlushLogFiles(google::INFO);
			packet::ptr_t pkt(new packet());
			pkt->sig(id());
			pkt->content_status(packet::content_failure);
			pkt->source(key.publisher);
			pkt->name(key.name);
			pkt->destination(node_.id());
			pkt->payload(boost::make_shared<payload_failure>(0));
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

