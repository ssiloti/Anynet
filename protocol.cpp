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

network_protocol::network_protocol(local_node& node) : node_(node), shutting_down_(false)
{
	node_id = node.id();
}

void network_protocol::register_handler()
{
	node_.register_protocol_handler(id(), shared_from_this());
}

void network_protocol::snoop_packet(packet::ptr_t pkt)
{
	snoop_packet_payload(pkt);

	if (pkt->content_status() == packet::content_requested) {
		std::pair<content_requests_t::iterator, bool> recent = recent_requests_.insert(std::make_pair(pkt->destination(), boost::array<boost::posix_time::ptime, 2>()));

		recent.first->second[1] = recent.first->second[0];
		recent.first->second[0] = boost::posix_time::second_clock::universal_time();

		DLOG(INFO) << "Couldn't locate content to satisfy request from " << std::string(pkt->source()) << " for " << std::string(pkt->destination());
	}
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
