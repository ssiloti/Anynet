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

#include "protocol.hpp"
#include "node.hpp"

#ifdef SIMULATION
#include "simulator.hpp"
#endif

const boost::posix_time::time_duration network_protocol::min_successor_source_age = boost::posix_time::hours(1);

network_protocol::network_protocol(local_node& node) : node_(node), vacume_sources_(node.io_service()), shutting_down_(false)
{
	node_id = node.id();
}

void network_protocol::register_handler()
{
	node_.register_protocol_handler(id(), shared_from_this());
}

void network_protocol::start_vacume()
{
	vacume_sources_.expires_from_now(boost::posix_time::minutes(1));
	vacume_sources_.async_wait(boost::bind(&network_protocol::vacume_sources, shared_from_this(), placeholders::error));
}

/*void network_protocol::register_source(network_key key, ip::tcp::endpoint source, size_t hunk_size)
{
	detached_content_source new_source;
	new_source.source = source;
	new_source.hunk_size = hunk_size;
	new_source.stored = boost::posix_time::second_clock::universal_time();
	new_source.last_access = new_source.stored;
	detached_hunk_sources_.insert(std::make_pair(key, new_source));
}

boost::iterator_range<network_protocol::detached_sources_t::const_iterator> network_protocol::get_sources(network_key key)
{
	return boost::iterator_range<detached_sources_t::const_iterator>(detached_hunk_sources_.lower_bound(key), detached_hunk_sources_.upper_bound(key));
}*/

void network_protocol::snoop_packet(packet::ptr_t pkt)
{
	switch (pkt->content_status())
	{
	case packet::content_requested:
		{
			const_payload_buffer_ptr content = get_content(pkt->destination());

			if (content) {
				DLOG(INFO) << "Replying with content to request from " << std::string(pkt->source()) << " for " << std::string(pkt->destination());
				pkt->to_reply(content);
				break;
			}

			content_sources_t::const_iterator detached_sources = content_sources_.find(pkt->destination());

			if (detached_sources != content_sources_.end() && detached_sources->second->sources.size() > 0) {
				DLOG(INFO) << "Respopnding with detached source to request from " << std::string(pkt->source()) << " for " << std::string(pkt->destination());
				pkt->to_reply(detached_sources->second);
				break;
			}

			DLOG(INFO) << "Couldn't locate content to satisfy request from " << std::string(pkt->source()) << " for " << std::string(pkt->destination());
			break;
		}
	case packet::content_attached:
		{
			pkt->source(store_content(pkt->payload()));
			break;
		}
	case packet::content_detached:
		{
			if (pkt->sources()->sources.size() > 1 && pkt->source() == pkt->destination()) {
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

	// see if we have an outstanding request which might be interested in this packet
	if (pkt->content_status() != packet::content_requested) {
		response_handlers_t::iterator keyed_handler = response_handlers_.find(pkt->source());

		if (keyed_handler != response_handlers_.end()) {
			if (keyed_handler->second->request.snoop_packet(node_, pkt)) {
			//	keyed_handler->second->timeout.cancel();
				response_handlers_.erase(keyed_handler);
			}
			else {
				// any time there's some activity on the request we reset the timeout
				keyed_handler->second->timeout.expires_from_now(boost::posix_time::seconds(5));
				keyed_handler->second->timeout.async_wait(boost::bind(&network_protocol::remove_response_handler, shared_from_this(), keyed_handler->first, placeholders::error));
			}
		}
	}
}

void network_protocol::snoop_fragment(ip::tcp::endpoint src, frame_fragment::ptr_t frag)
{
	if (!frag->is_request()) {
		response_handlers_t::iterator request = response_handlers_.find(frag->id());

		if (request != response_handlers_.end()) {
			const_payload_buffer_ptr payload = request->second->request.snoop_fragment(node_, src, frag);

			if (payload) {
				packet::ptr_t pkt(new packet());
				pkt->protocol(id());
				pkt->content_status(packet::content_attached);
				pkt->destination(node_.id());
				pkt->payload(payload);
				snoop_packet(pkt);
				return;
			}
			else if (frag->status() == frame_fragment::status_failed) {
				packet::ptr_t pkt(new packet());
				pkt->protocol(id());
				pkt->content_status(packet::content_failure);
				pkt->source(frag->id());
				pkt->destination(node_.id());
				pkt->payload(packet::not_found);
				if (request->second->request.snoop_packet(node_, pkt)) {
				//	request->second->timeout.cancel();
					response_handlers_.erase(request);
					return;
				}
			}

			// any time there's some activity on the request we reset the timeout
			request->second->timeout.expires_from_now(boost::posix_time::seconds(5));
			request->second->timeout.async_wait(boost::bind(&network_protocol::remove_response_handler, shared_from_this(), request->first, placeholders::error));
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

content_sources::ptr_t network_protocol::get_content_sources(network_key id, std::size_t size)
{
	std::pair<content_sources_t::iterator, bool> found_sources = content_sources_.insert( std::make_pair( id, content_sources::ptr_t() ) );

	if (found_sources.second)
		found_sources.first->second.reset(new content_sources(size));

	return found_sources.first->second;
}

framented_content::fragment_buffer network_protocol::get_fragment_buffer(frame_fragment::ptr_t frag)
{
	response_handlers_t::iterator request = response_handlers_.find(frag->id());

	if (request != response_handlers_.end())
		return request->second->request.get_fragment_buffer(frag->offset(), frag->size());
	else
		return framented_content::fragment_buffer(frag->offset());
}

void network_protocol::new_content_request(const network_key& key, const content_request::keyed_handler_t& handler)
{
	std::pair<response_handlers_t::iterator, bool> rh = response_handlers_.insert(std::make_pair(key, boost::shared_ptr<response_handler>()));

	if (rh.second) {
		rh.first->second.reset(new response_handler(node_.io_service()));
		rh.first->second->timeout.async_wait(boost::bind(&network_protocol::remove_response_handler, shared_from_this(), rh.first->first, placeholders::error));
	}

	if (handler)
		rh.first->second->request.add_handler(handler);

	if (rh.second)
		rh.first->second->request.initiate_request(id(), key, node_);
}

void network_protocol::remove_response_handler(network_key key, const boost::system::error_code& error)
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
			pkt->payload(packet::not_found);
			if (iter->second->request.timeout(node_, pkt))
				// request has nothing more to do, put him out of his misery
				response_handlers_.erase(iter);
			else {
				// we had a timeout but the request still has sources to try, reset the timer
				iter->second->timeout.expires_from_now(boost::posix_time::seconds(5));
				iter->second->timeout.async_wait(boost::bind(&network_protocol::remove_response_handler, shared_from_this(), iter->first, placeholders::error));
			}
		}
	}
}

bool network_protocol::attach_remote_request_handler(const network_key& key, const network_key& requester)
{
	response_handlers_t::iterator keyed_handler = response_handlers_.find(key);
	if (keyed_handler != response_handlers_.end()) {
		DLOG(INFO) << "Attaching remote request to existing request";
		keyed_handler->second->request.add_handler(remote_request_handler(*this, requester, key));
		return true;
	}
	else
		return false;
}

void network_protocol::remote_request_handler::operator()(const_payload_buffer_ptr content)
{
	packet::ptr_t pkt(new packet());
	pkt->protocol(protocol_.id());
	pkt->source(requested);
	pkt->destination(requester);
	if (content) {
		pkt->payload(content);
		pkt->content_status(packet::content_attached);
	}
	else {
		pkt->payload(packet::not_found);
		pkt->content_status(packet::content_failure);
	}

	connection::ptr_t con = protocol_.pickup_crumb(std::make_pair(requester, requested));

	if (con)
		con->send(pkt);
	else
		protocol_.node_.dispatch(pkt);
}

void network_protocol::drop_crumb(const std::pair<network_key, network_key>& k, boost::weak_ptr<connection> c)
{
	std::pair<crumbs_t::iterator, bool> result = crumbs_.insert(std::make_pair(k, boost::shared_ptr<crumb>()));
	if (result.second) {
		DLOG(INFO) << std::string(node_.id()) << " Dropping crmumb id " << std::string(k.first) << ", " << std::string(k.second) << " source " << std::string(c.lock()->remote_id());
		result.first->second.reset(new crumb(c, node_.io_service()));
		result.first->second->timeout.async_wait(boost::bind(&network_protocol::pickup_crumb, shared_from_this(), k, placeholders::error));
	}
}

boost::shared_ptr<connection> network_protocol::pickup_crumb(const std::pair<network_key, network_key>& k, const boost::system::error_code& error)
{
	boost::shared_ptr<connection> con;

	if (!error) {
		crumbs_t::iterator crumb_trail = crumbs_.find(k);

		if (crumb_trail != crumbs_.end()) {
			DLOG(INFO) << std::string(node_.id()) << " Picking up crmumb id " << std::string(k.first) << ", " << std::string(k.second);
			con = crumb_trail->second->con.lock();
			crumbs_.erase(crumb_trail);
		}
	}

	return con;
}

boost::shared_ptr<connection> network_protocol::get_crumb(const std::pair<network_key, network_key>& k)
{
	crumbs_t::iterator crumb_trail = crumbs_.find(k);
	boost::shared_ptr<connection> con;

	if (crumb_trail != crumbs_.end())
		con = crumb_trail->second->con.lock();

	return con;
}

void network_protocol::vacume_sources(const boost::system::error_code& error)
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
		vacume_sources_.async_wait(boost::bind(&network_protocol::vacume_sources, shared_from_this(), placeholders::error));
	}
	else if (!error)
		DLOG(INFO) << std::string(node_.id()) << ": Vacuming sources";
}
