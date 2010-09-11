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

#include "signature_scheme.hpp"
#include "node.hpp"
#include <boost/bind/protect.hpp>

#ifdef SIMULATION
#include "simulator.hpp"
#endif

const boost::posix_time::time_duration signature_scheme::min_successor_source_age = boost::posix_time::hours(1);

sendable_payload::ptr_t content_sources::get_payload()
{
	if (sources.empty())
		return sendable_payload::ptr_t();
	else if (sources.begin()->second.ep.address().is_v4())
		return boost::make_shared<payload_content_sources_v4>(shared_from_this());
	else
		return boost::make_shared<payload_content_sources_v6>(shared_from_this());
}

signature_scheme::signature_scheme(local_node& node, signature_scheme_id p)
	: node_(node), shutting_down_(false), vacume_sources_(node.io_service()), protocol_(p)
{
	node_id = node.id();
}

void signature_scheme::receive_payload(connection::ptr_t con, packet::ptr_t pkt, std::size_t payload_size)
{
	if (payload_size == 0 && pkt->content_status() != packet::content_attached) {
		packet::ptr_t p;
		node_.packet_received(con, p);
		return;
	}

	switch (pkt->content_status())
	{
	case packet::content_attached:
		receive_attached_content(con, pkt, payload_size);
		break;
	case packet::content_detached:
		con->receive_payload(payload_size, boost::protect(boost::bind(&signature_scheme::sources_received, this, con, pkt, _1)));
		break;
	case packet::content_requested:
		con->receive_payload(payload_size, boost::protect(boost::bind(&signature_scheme::request_received, this, con, pkt, _1)));
		break;
	case packet::content_failure:
		con->receive_payload(payload_size, boost::protect(boost::bind(&signature_scheme::failure_received, this, con, pkt, _1)));
		break;
	}
}

void signature_scheme::register_handler()
{
	node_.register_protocol_handler(id(), shared_from_this());
}

content_sources::ptr_t signature_scheme::get_content_sources(content_identifier id, content_size_t size)
{
	std::pair<content_sources_t::iterator, bool> found_sources = content_sources_.insert( std::make_pair( id, content_sources::ptr_t() ) );

	if (found_sources.second)
		found_sources.first->second.reset(new content_sources(size));

	return found_sources.first->second;
}

void signature_scheme::snoop_packet(packet::ptr_t pkt)
{
	snoop_packet_payload(pkt);

	if (pkt->content_status() == packet::content_requested) {
		std::pair<content_requests_t::iterator, bool> recent = recent_requests_.insert(std::make_pair(pkt->content_id(), boost::array<boost::posix_time::ptime, 2>()));

		recent.first->second[1] = recent.first->second[0];
		recent.first->second[0] = boost::posix_time::second_clock::universal_time();

		DLOG(INFO) << "Couldn't locate content to satisfy request from " << std::string(pkt->source()) << " for " << std::string(pkt->destination());
	}
}

void signature_scheme::drop_crumb(packet::ptr_t pkt, boost::weak_ptr<connection> con)
{
	std::pair<crumbs_t::iterator, bool> crumb_entry = crumbs_.insert(std::make_pair(pkt->content_id(), boost::shared_ptr<crumb>()));
	if (crumb_entry.second) {
		crumb_entry.first->second.reset(new crumb(node_.io_service()));
		crumb_entry.first->second->timeout.async_wait(boost::bind(&signature_scheme::pickup_crumb, shared_from_this(), pkt->content_id(), placeholders::error));
	}

	std::pair<crumb::requesters_t::iterator, bool> requester_entry = crumb_entry.first->second->requesters.insert(std::make_pair(pkt->requester(), con));
	requester_entry.first->second = con; // even if there already was an entry for this requester, update the connection pointer to point to the most recent request

	DLOG(INFO) << std::string(node_.id()) << " Dropping crmumb id "
	           << std::string(pkt->content_id().publisher) << ", " << std::string(pkt->requester()) << " source " << std::string(con.lock()->remote_id());
}

void signature_scheme::pickup_crumb(packet::ptr_t pkt)
{
	pickup_crumb(pkt->content_id(), boost::system::error_code());
}

void signature_scheme::pickup_crumb(const content_identifier& cid, const boost::system::error_code& error)
{
	if (!error) {
		crumbs_t::iterator crumb_trail = crumbs_.find(cid);

		if (crumb_trail != crumbs_.end()) {
			DLOG(INFO) << std::string(node_.id()) << " Picking up crmumb id " << std::string(cid.publisher);
			crumbs_.erase(crumb_trail);
		}
	}
}

boost::optional<const signature_scheme::crumb::requesters_t&> signature_scheme::get_crumb(packet::ptr_t pkt)
{
	crumbs_t::iterator crumb_trail = crumbs_.find(pkt->content_id());

	if (crumb_trail != crumbs_.end())
		return crumb_trail->second->requesters;
	else
		return boost::optional<const signature_scheme::crumb::requesters_t&>();
}

void signature_scheme::receive_attached_content(connection::ptr_t con, packet::ptr_t pkt, std::size_t payload_size)
{
	// nodes should not be sending us attached content with a signature we don't understand
	// report this as an error so the node can deal with the offending peer appropriately
	packet::ptr_t p;
	node_.packet_received(con, p);
}

void signature_scheme::sources_received(connection::ptr_t con, packet::ptr_t pkt, const_buffer buf)
{
	if (con->remote_endpoint().address().is_v4())
		payload_content_sources_v4::parse(pkt, buf, *this);
	else
		payload_content_sources_v6::parse(pkt, buf, *this);
	node_.packet_received(con, pkt);
}

void signature_scheme::request_received(connection::ptr_t con, packet::ptr_t pkt, const_buffer buf)
{
	payload_request::parse(pkt, buf);
	node_.packet_received(con, pkt);
}

void signature_scheme::failure_received(connection::ptr_t con, packet::ptr_t pkt, const_buffer buf)
{
	payload_failure::parse(pkt, buf);
	node_.packet_received(con, pkt);
}

void signature_scheme::start_vacume()
{
	vacume_sources_.expires_from_now(boost::posix_time::minutes(1));
	vacume_sources_.async_wait(boost::bind(&signature_scheme::vacume_sources,
	                                       boost::static_pointer_cast<signature_scheme>(shared_from_this()),
	                                       _1)); // TODO: Using boost::asio::placeholders::error here results in
	                                             // a null pointer dereference!? Need to understand what the hell is
	                                             // up with that
}

void signature_scheme::vacume_sources(const boost::system::error_code& error)
{
	if (!error && !shutting_down_) {
		boost::posix_time::ptime now = boost::posix_time::second_clock::universal_time();
		boost::posix_time::time_duration age_cap = node_.base_hunk_lifetime();

		for (content_sources_t::iterator content = content_sources_.begin(); content != content_sources_.end();) {
			bool successor = node_.closer_peers(content->first.publisher) == 0;
			for (content_sources::sources_t::iterator source = content->second->sources.begin(); source != content->second->sources.end();) {
				boost::posix_time::time_duration age = now - source->second.stored;
				if ( (age < age_cap) || (successor && age < min_successor_source_age) || source->second.active_request_count ) {
					++source;
				}
				else {
					content_sources::sources_t::iterator next = source;
					++next;
					content->second->sources.erase(source);
					source = next;
				}
			}

			if (!content->second->sources.empty()) {
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
		vacume_sources_.async_wait(boost::bind(&signature_scheme::vacume_sources,
		                                       boost::static_pointer_cast<signature_scheme>(shared_from_this()),
		                                       placeholders::error));
	}
	else if (!error)
		DLOG(INFO) << std::string(node_.id()) << ": Vacuming sources";
}
