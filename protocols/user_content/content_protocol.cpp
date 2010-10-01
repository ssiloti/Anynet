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

#include "fragment.hpp"
#include "payload_content_buffer.hpp"
#include "content_protocol.hpp"
#include <payload_sources.hpp>
#include <payload_request.hpp>
#include <payload_failure.hpp>
#include <node.hpp>
#include <boost/bind/protect.hpp>
#include <boost/bind.hpp>
#include <boost/make_shared.hpp>
#include <memory>

using namespace user_content;

content_protocol::content_protocol(local_node& node, protocol_id p)
	: network_protocol(node, p)
{}

void content_protocol::to_content_location_failure(packet::ptr_t pkt)
{
	pkt->to_reply(packet::content_failure, boost::make_shared<payload_failure>(pkt->payload_as<payload_request>()->size));
}

void content_protocol::request_from_location_failure(packet::ptr_t pkt)
{
	pkt->to_reply(packet::content_requested, boost::make_shared<payload_request>(pkt->payload_as<payload_failure>()->size));
}

void content_protocol::snoop_packet_payload(packet::ptr_t pkt)
{
	switch (pkt->content_status())
	{
	case packet::content_requested:
		{
			const_payload_buffer_ptr content = get_content(pkt->content_id());

			if (content) {
				DLOG(INFO) << "Replying with content to request from " << std::string(pkt->source()) << " for " << std::string(pkt->destination());
				if (pkt->payload_as<payload_request>()->min_oob_threshold < buffer_size(content->get())) {
					content_sources::ptr_t self_source(boost::make_shared<content_sources>(buffer_size(content->get())));
					self_source->sources.insert(content_sources::sources_t::value_type(node_.id(), node_.public_endpoint()));
					if (node_.is_v4())
						pkt->to_reply(packet::content_detached, boost::make_shared<payload_content_sources_v4>(self_source));
					else
						pkt->to_reply(packet::content_detached, boost::make_shared<payload_content_sources_v6>(self_source));
				}
				else
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
				hunk_desc = node_.cache_local_request(id(),
				                                      pkt->content_id(),
				                                      buffer_size(pkt->payload_as<payload_content_buffer>()->payload->get()));
			}
			else if (pkt->source() == pkt->destination())
				hunk_desc = node_.cache_store(id(),
				                              pkt->content_id(),
				                              buffer_size(pkt->payload_as<payload_content_buffer>()->payload->get()));
			else {
				content_requests_t::iterator recent_request = recent_requests_.find(pkt->content_id());
				if (recent_request == recent_requests_.end() || recent_request->second[1].is_not_a_date_time())
					break;
				hunk_desc = node_.cache_remote_request(id(),
				                                       pkt->content_id(),
				                                       buffer_size(pkt->payload_as<payload_content_buffer>()->payload->get()),
				                                       recent_request->second[0] - recent_request->second[1]);
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
	else if (pkt->content_status() == packet::content_detached) {
		content_requests_t::iterator recent_request = recent_requests_.find(pkt->content_id());
		content_size_t content_size = pkt->payload_as<boost::shared_ptr<content_sources> >()->get()->size;
		if (!(recent_request == recent_requests_.end() || recent_request->second[1].is_not_a_date_time())
		    && content_size <= node_.average_oob_threshold()) {
			hunk_descriptor_t hunk_desc;
			hunk_desc = node_.cache_remote_request(id(),
			                                       pkt->content_id(),
			                                       std::size_t(content_size),
			                                       recent_request->second[0] - recent_request->second[1]);
			if (hunk_desc != node_.not_a_hunk()) {
				// We have detached sources, the associated content has been requested at least twice,
				// the content is small enough for us to send in-band, and we have enough cache space
				// to store it. Lets go ahead an start a request for the content so we can attach it
				// to future responses.
				new_content_request(pkt->content_id(),
				                    std::size_t(content_size),
				                    boost::bind(&content_protocol::completed_detached_content_request,
				                                shared_from_this_as<content_protocol>(),
				                                hunk_desc,
				                                _1));
			}
		}
	}

	if (pkt->content_status() != packet::content_requested) {
		// see if we have an outstanding request which might be interested in this packet
		response_handlers_t::iterator keyed_handler = response_handlers_.find(pkt->content_id());

		if (keyed_handler != response_handlers_.end()) {
			if (keyed_handler->second->request.snoop_packet(node_, pkt)) {
				response_handlers_.erase(keyed_handler);
			}
			else {
				// any time there's some activity on the request we reset the timeout
				keyed_handler->second->timeout.expires_from_now(boost::posix_time::seconds(5));
				keyed_handler->second->timeout.async_wait(boost::bind(&content_protocol::remove_response_handler,
				                                                      shared_from_this_as<content_protocol>(),
				                                                      keyed_handler->first,
				                                                      placeholders::error));
			}
		}
	}
}

void content_protocol::snoop_fragment(const network_key& src, frame_fragment::ptr_t frag)
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
				pkt->name(frag->id().name);
				pkt->payload(boost::make_shared<payload_content_buffer>(boost::ref(node_), payload));
				snoop_packet(pkt);
				return;
			}
			else if (frag->status() == frame_fragment::status_failed) {
				packet::ptr_t pkt(new packet());
				pkt->protocol(id());
				pkt->content_status(packet::content_failure);
				pkt->source(frag->id().publisher);
				pkt->name(frag->id().name);
				pkt->destination(node_.id());
				pkt->payload(boost::make_shared<payload_failure>(0));
				if (request->second->request.snoop_packet(node_, pkt)) {
					response_handlers_.erase(request);
					return;
				}
			}

			// any time there's some activity on the request we reset the timeout
			request->second->timeout.expires_from_now(boost::posix_time::seconds(5));
			request->second->timeout.async_wait(boost::bind(&content_protocol::remove_response_handler,
			                                                shared_from_this_as<content_protocol>(),
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

void content_protocol::receive_attached_content(connection::ptr_t con, packet::ptr_t pkt, std::size_t payload_size)
{
	payload_buffer_ptr payload_buffer(get_payload_buffer(payload_size));
	pkt->payload(boost::make_shared<payload_content_buffer>(boost::ref(node_), payload_buffer));
	con->receive_payload(std::vector<mutable_buffer>(1,
	                                                 payload_buffer->get()),
	                                                 boost::protect(boost::bind(&content_protocol::content_received, this, con, pkt)));
}

void content_protocol::content_received(connection::ptr_t con, packet::ptr_t pkt)
{
	node_.packet_received(con, pkt);
}

void content_protocol::incoming_frame(connection::ptr_t con, boost::uint8_t frame_type)
{
	switch (frame_type)
	{
	case frame_type_fragment:
		{
			frame_fragment::ptr_t frag(boost::make_shared<frame_fragment>(id()));
			con->receive_payload(frag,
			                     shared_from_this_as<content_protocol>(),
			                     boost::protect(boost::bind(&content_protocol::fragment_received,
			                                                shared_from_this_as<content_protocol>(),
			                                                con,
			                                                frag)));
			break;
		}
	default:node_.receive_failure(con);break;
	}
}

void content_protocol::fragment_received(connection::ptr_t con, boost::shared_ptr<frame_fragment> frag)
{
	con->send_ack();
	// FIXME: This is ugly, there must be a better way to send the reply
	frame_fragment::fragment_status old_status = frag->status();
	snoop_fragment(con->remote_id(), frag);
	if (old_status == frame_fragment::status_requested && old_status != frag->status())
		node_.direct_request(con->remote_endpoint(), frag);
}

framented_content::fragment_buffer content_protocol::get_fragment_buffer(frame_fragment::ptr_t frag)
{
	response_handlers_t::iterator request = response_handlers_.find(frag->id());

	if (request != response_handlers_.end())
		return request->second->request.get_fragment_buffer(frag->offset(), frag->size());
	else
		return framented_content::fragment_buffer(frag->offset());
}

void content_protocol::new_content_request(const content_identifier& key,
                                           content_size_t content_size,
                                           const content_request::keyed_handler_t& handler)
{
	std::pair<response_handlers_t::iterator, bool>
		rh = response_handlers_.insert(std::make_pair(key, boost::shared_ptr<response_handler>()));

	if (rh.second) {
		rh.first->second = boost::make_shared<response_handler>(boost::ref(node_.io_service()));
		rh.first->second->timeout.async_wait(boost::bind(&content_protocol::remove_response_handler,
		                                                 shared_from_this_as<content_protocol>(),
		                                                 rh.first->first,
		                                                 placeholders::error));
	}

	if (handler)
		rh.first->second->request.add_handler(handler);

	if (rh.second)
		rh.first->second->request.initiate_request(id(), key, node_, content_size);
}

void content_protocol::new_content_store(content_identifier cid, const_payload_buffer_ptr hunk)
{
	// New content stores must always be done detached. Clients can't be counted on
	// to cache unsolicited data but they will store content sources. Even if nodes
	// generally did cache unsolicited data it could get detached mid-way to the
	// content's successor due to oob thresholds. In this case we would really rather
	// the stored content source to be us over some intermediate node who probably isn't
	// going to hold the content very long.
	DLOG(INFO) << "New store request for cid " << std::string(cid.publisher);
	packet::ptr_t pkt(new packet());
	pkt->destination(cid.publisher);
	pkt->source(cid.publisher);
	pkt->name(cid.name);
	pkt->protocol(id());
	content_sources::ptr_t self_source(boost::make_shared<content_sources>(buffer_size(hunk->get())));
	self_source->sources.insert(std::make_pair(node_.id(), content_sources::source(node_.public_endpoint())));
	pkt->content_status(packet::content_detached);
	if (node_.is_v4())
		pkt->payload(boost::make_shared<payload_content_sources_v4>(self_source));
	else
		pkt->payload(boost::make_shared<payload_content_sources_v6>(self_source));
	node_.local_request(pkt);
}

void content_protocol::remove_response_handler(content_identifier key, const boost::system::error_code& error)
{
	if (!error) {
		DLOG(INFO) << std::string(node_.id()) << ": Removing response handler " << std::string(key.publisher);
		response_handlers_t::iterator iter = response_handlers_.find(key);
		if (iter != response_handlers_.end()) {
			google::FlushLogFiles(google::INFO);
			packet::ptr_t pkt(new packet());
			pkt->protocol(id());
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
				iter->second->timeout.async_wait(boost::bind(&content_protocol::remove_response_handler,
				                                             shared_from_this_as<content_protocol>(),
				                                             iter->first,
				                                             placeholders::error));
			}
		}
	}
}

void content_protocol::completed_detached_content_request(hunk_descriptor_t desc, const_payload_buffer_ptr content)
{
	if (!content)
		node_.erase_hunk(desc);
	else
		store_content(desc, content);
}
