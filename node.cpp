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

#include "node.hpp"
#include "config.hpp"
#include "peer_cache.hpp"
#include "packet.hpp"
#include "connection.hpp"
#include <boost/bind/protect.hpp>
#include <boost/accumulators/accumulators.hpp>
#include <boost/accumulators/statistics/mean.hpp>
#include <boost/accumulators/statistics/variance.hpp>
#include <limits>

#ifdef SIMULATION
#include "simulator.hpp"
#endif

local_node::local_node(boost::asio::io_service& io_service, client_config& config)
	: config_(config), acceptor_(io_service, ip::tcp::endpoint(ip::address::from_string(config.listen_ip()), config.listen_port())),
	  public_endpoint_(acceptor_.local_endpoint()), created_(boost::posix_time::second_clock::universal_time())
#ifdef SIMULATION
	  , heal_timer_(io_service)
#endif
	  
{
	connection::accept(*this, acceptor_);
	bootstrap();
}

local_node::~local_node()
{
	while (!ib_peers_.empty()) {
		// in-band peers need a little special handling to prevent them from re-dispatching packets to themselves
		connection::ptr_t con = ib_peers_.back();
		ib_peers_.pop_back();
		con->disconnect();
	}
	for (std::vector<oob_peer::ptr_t>::iterator it = oob_peers_.begin(); it != oob_peers_.end(); ++it)
		(*it)->con->disconnect();
	for (std::vector<connection::ptr_t>::iterator it = connecting_peers_.begin(); it != connecting_peers_.end(); ++it)
		(*it)->disconnect();

	for (std::map<protocol_t, network_protocol::ptr_t>::iterator it = protocol_handlers_.begin(); it != protocol_handlers_.end(); ++it)
		it->second->shutdown();
}

template <network_key dist_fn(const network_key& src, const network_key& dest)>
std::vector<connection::ptr_t>::iterator local_node::get_sucessor(const network_key& outer_id, const network_key& inner_id, const network_key& key, std::size_t content_size)
{
	network_key max_dist = dist_fn(key, outer_id);
	network_key min_dist = dist_fn(key, inner_id);

	double best_score = 1.0;

	std::vector<connection::ptr_t>::iterator best_peer(ib_peers_.end());

	assert(max_dist >= min_dist);

	long node_age = age().total_seconds();

	for (std::vector<connection::ptr_t>::iterator it = ib_peers_.begin(); it != ib_peers_.end(); ++it) {
		network_key dist = dist_fn(key, (*it)->remote_id());
		if (dist < max_dist && dist >= min_dist) {
			double score = dist / max_dist;
			assert(score < 1.0);
			score *= 0.75;

			double age_term;
			if (node_age == 0)
				age_term = 0.0;
			else
				age_term = 1.0 - double((*it)->age().total_seconds()) / double(node_age);
			assert(age_term <= 1.0);
			score += ( age_term ) * 0.25;

			assert(score < 1.0);
			// We want to favor peers who can take the content directly over those who cant, even if it results in picking a worse match in terms of score
			if (( score < best_score && (best_peer == ib_peers_.end() || content_size <= (*it)->oob_threshold() || content_size > (*best_peer)->oob_threshold()) )
				|| ( content_size > (*best_peer)->oob_threshold() && content_size <= (*it)->oob_threshold() )) {
				best_score = score;
				best_peer = it;
			}
		}
	}

	return best_peer;
}

template <network_key dist_fn(const network_key& src, const network_key& dest)>
std::vector<connection::ptr_t>::iterator local_node::get_strict_sucessor(const network_key& outer_id, const network_key& inner_id, const network_key& key, std::size_t content_size)
{
	network_key max_dist = dist_fn(key, outer_id);
	network_key min_dist = dist_fn(key, inner_id);

	network_key best_dist = max_dist;

	std::vector<connection::ptr_t>::iterator best_peer(ib_peers_.end());

	assert(max_dist >= min_dist);

	for (std::vector<connection::ptr_t>::iterator it = ib_peers_.begin(); it != ib_peers_.end(); ++it) {
		network_key dist = dist_fn(key, (*it)->remote_id());
		if (dist < best_dist && dist >= min_dist) {
			best_dist = dist;
			best_peer = it;
		}
	}

	return best_peer;
}

network_key local_node::self_reverse_sucessor()
{
	std::vector<connection::ptr_t>::iterator successor = get_strict_sucessor<reverse_distance>(id()-1, id()+1, id());

	if (successor != ib_peers_.end())
		return (*successor)->remote_id();
	else
		return id();
}

ip::tcp::endpoint local_node::sucessor_endpoint(const network_key& key)
{
	std::vector<connection::ptr_t>::iterator target = get_sucessor<distance>(id(), key, key);

	if (target != ib_peers_.end())
		return (*target)->remote_endpoint();
	else
		return public_endpoint();
}

ip::tcp::endpoint local_node::reverse_sucessor_endpoint(const network_key& key)
{
	std::vector<connection::ptr_t>::iterator target = get_sucessor<reverse_distance>(id(), key + 1, key);

	if (target != ib_peers_.end())
		return (*target)->remote_endpoint();
	else
		return public_endpoint();
}

std::vector<connection::ptr_t>::iterator local_node::sucessor(const network_key& key, const network_key& inner_id, std::size_t content_size)
{
	return get_sucessor<distance>(id(), inner_id, key, content_size);
}

void local_node::register_connection(connection::ptr_t con)
{
	if (con && con->is_connected()) {
		DLOG(INFO) << "Connection established " << config_.listen_port() << ", " << con->remote_endpoint().port();

		reported_addresses_.insert(con->reported_node_address());
		recompute_identity();
		connecting_peers_.erase(std::find(connecting_peers_.begin(), connecting_peers_.end(), con));
		if (con->accepts_ib_traffic()) {
			DLOG(INFO) << "New in-band Connection established";
			ib_peers_.push_back(con);

			// check to see if this guy is the new successor for us
			std::vector<connection::ptr_t>::iterator successor = get_strict_sucessor<distance>(id()+1, id()-1, id());

			if (successor == --ib_peers_.end()) {
				DLOG(INFO) << "Got new successor, checking to notify old successor";
				// he is, see if we had a previous successor
				std::vector<connection::ptr_t>::iterator old_successor = get_strict_sucessor<distance>(id()+1, (*successor)->remote_id()-1, id());

				if (old_successor != ib_peers_.end()) {
					DLOG(INFO) << "Old Successor found (" << std::string((*old_successor)->remote_id()) << "), notifying";
					// we did, let him know about this new peer, he is likely to be of interest to him as a reverse successor
					(*old_successor)->send_reverse_successor();
				}
			}
		}
		else {
			oob_peers_.push_back(oob_peer::create(*this, con));
		}

	//	con->receive_packet(packet::ptr_t(new packet()), boost::protect(boost::bind(&local_node::incoming_packet, this, con, _1, _2)));

#if 0
		if (sucessor.address() == ip::address_v4() || sucessor.address() == ip::address_v6())
			sucessor = con->remote_endpoint();
/*
		if ((con->oob_threshold() && con->remote_endpoint() != sucessor) || (!connection_count() && con->remote_endpoint() == sucessor)) {
			connection::connect(*this, sucessor, true);
			for (std::vector<ip::tcp::endpoint>::iterator peer = finger_queue_.begin(); peer != finger_queue_.end(); ++peer)
				connection::connect(*this, *peer, true);
		}
		else if (!connection_count()) {
			finger_queue_.push_back(con->remote_endpoint());
			connection::connect(*this, sucessor, false);
		}*/
		if (con->remote_endpoint() != sucessor || !connection_count()) {
			make_connection(sucessor);
		}
#endif
	}
	else if (connection_count() == 0)
		bootstrap();
}

void local_node::bootstrap()
{
	ip::tcp::endpoint seed_peer;
	
	do {
		seed_peer = peer_cache.get_peer();
#ifdef SIMULATION
		if (seed_peer.port() == config_.listen_port() && peer_cache.peer_count() == 1) {
			seed_peer = ip::tcp::endpoint();
			break;
		}
	} while (seed_peer != ip::tcp::endpoint() && seed_peer.port() == config_.listen_port());
#else
	} while (seed_peer != ip::tcp::endpoint() && seed_peer == public_endpoint());
#endif

	if (seed_peer != ip::tcp::endpoint())
		make_connection(seed_peer);
}

connection::ptr_t local_node::local_request(packet::ptr_t pkt)
{
	snoop(pkt);
	return dispatch(pkt);
}

connection::ptr_t local_node::local_request(packet::ptr_t pkt, const network_key& inner_id)
{
	snoop(pkt);

	if (pkt->content_status() == packet::content_requested) {
		if (::distance(pkt->destination(), inner_id) < ::distance(pkt->destination(), id())) {
			connection::ptr_t con = dispatch(pkt, inner_id, true);
			if (con)
				return con;
		}

		// We've got nobody left closer to the content, time to go into desperation mode.
		// We'll now ask any remaining peers for the content, even if they are farther away
		// from the content than us. These peers won't forward the request, but if they can satisfy it
		// themselves they will send it back to us. This is more likely to happen if we are close
		// to the content, so it might actually have a decent chance of success.

		DLOG(INFO) << std::string(id()) << ": Initiating desperation for local request, content: " << std::string(pkt->destination());

		// we don't want this packet going back through the normal dispatch path
		pkt->mark_direct();

		std::vector<connection::ptr_t>::iterator target = get_sucessor<distance>(pkt->destination() + 1, inner_id, pkt->destination(), 0);

		if (target != ib_peers_.end()) {
			(*target)->send(pkt);
			return *target;
		}
	}

	return connection::ptr_t();
}

struct con_ep_cmp
{
	con_ep_cmp(ip::tcp::endpoint peer) : ep(peer) {}

	bool operator()(connection::ptr_t con)
	{
		return con->remote_endpoint() == ep;
	}

	ip::tcp::endpoint ep;
};

struct oob_con_ep_cmp
{
	oob_con_ep_cmp(ip::tcp::endpoint peer) : ep(peer) {}

	bool operator()(local_node::oob_peer::ptr_t peer)
	{
		return peer->con->remote_endpoint() == ep;
	}

	ip::tcp::endpoint ep;
};

void local_node::direct_request(ip::tcp::endpoint peer, frame_fragment::ptr_t frag)
{
	std::vector<connection::ptr_t>::iterator con_iter = std::find_if(ib_peers_.begin(), ib_peers_.end(), con_ep_cmp(peer));
	connection::ptr_t con;

	if (con_iter == ib_peers_.end()) {
		std::vector<oob_peer::ptr_t>::iterator ocon_iter = std::find_if(oob_peers_.begin(), oob_peers_.end(), oob_con_ep_cmp(peer));
		if (ocon_iter == oob_peers_.end()) {
			con_iter = std::find_if(connecting_peers_.begin(), connecting_peers_.end(), con_ep_cmp(peer));
			if (con_iter == connecting_peers_.end())
				con = connection::connect(*this, peer, connection::oob);
			else
				con = *con_iter;
		}
		else {
			con = (*ocon_iter)->con;
			(*ocon_iter)->reset_timeout();
		}
	}
	else
		con = *con_iter;

	con->send(frag);
}

void local_node::snoop(packet::ptr_t pkt)
{
	std::map<protocol_t, network_protocol::ptr_t>::iterator protocol_handler = protocol_handlers_.find(pkt->protocol());

	if (protocol_handler == protocol_handlers_.end()) {
		// TODO: Turn the packet around with an error, for now just drop it
		DLOG(INFO) << "Unknown packet protocol! " << pkt->protocol();
		return;
	}

	protocol_handler->second->snoop_packet(pkt);
}

connection::ptr_t local_node::dispatch(packet::ptr_t pkt)
{
	return dispatch(pkt, pkt->destination());
}

connection::ptr_t local_node::dispatch(packet::ptr_t pkt, const network_key& inner_id, bool local_request )
{	
/*	if (pkt->content_status() != packet::content_requested) {
		connection::ptr_t con = get_protocol(pkt).pickup_crumb(pkt->destination());
		if (con) {
			con->send(pkt);
			return con;
		}
	}*/

	std::size_t content_size;

	switch (pkt->content_status()) {
	case packet::content_attached:
		content_size = buffer_size(pkt->payload()->get());
		break;
	case packet::content_detached:
		content_size = pkt->sources()->size;
		break;
	default:
		content_size = 0;
	}

	std::vector<connection::ptr_t>::iterator target = sucessor(pkt->destination(), inner_id, content_size);

	if (target != ib_peers_.end()) {
		DLOG(INFO) << "Got successor peer " << std::string((*target)->remote_id());
		if (pkt->content_status() == packet::content_detached && content_size < (*target)->oob_threshold()) {
			// we have detached content but it is smaller than our oob threshold so we could send it attached.
			// instead of forwarding the sources we will start a local request for the content then send it
			// attached
			assert(false);
		}
		else
			(*target)->send(pkt);
		return *target;
	}
	/*else if (pkt->content_status() == packet::content_requested) {
			DLOG(INFO) << "Failed to process packet, dest=" << std::string(pkt->destination());
			pkt->to_reply(packet::not_found);

			if (!local_request)
				snoop(pkt);

			return dispatch(pkt);
	}*/
	else
		return connection::ptr_t();
}

void local_node::incoming_packet(connection::ptr_t con, packet::ptr_t pkt, std::size_t payload_size)
{
	if (!pkt) {
		// There was an error receiving the packet, don't bother trying to receive another, just let the connection die
		disconnect_peer(con);
		return;
	}

	std::map<protocol_t, network_protocol::ptr_t>::iterator protocol_handler = protocol_handlers_.find(pkt->protocol());

	if (protocol_handler == protocol_handlers_.end())
	{
		// TODO: return error unkown protocol
		return;
	}

	if (payload_size == 0)
		packet_received(con, pkt);
	else {
		switch (pkt->content_status())
		{
		case packet::content_attached:
			con->receive_payload(pkt,
								 protocol_handler->second->get_payload_buffer(payload_size),
								 boost::protect(boost::bind(&local_node::packet_received, this, con, _1)));
			break;
		case packet::content_detached:
			con->receive_payload(pkt,
			                     protocol_handler->second->get_content_sources(pkt->source(), payload_size),
			                     boost::protect(boost::bind(&local_node::packet_received, this, con, _1)));
			break;
		case packet::content_requested:
			{
				// TODO: return an error packet to let our neighbor know that we're chucking his extra data
				payload_buffer_ptr buf(new heap_buffer(payload_size));
				con->receive_payload(pkt,
				                     buf,
				                     boost::protect(boost::bind(&local_node::packet_received, this, con, _1)));
			}
			break;
		}
		
	}
}

void local_node::packet_received(connection::ptr_t con, packet::ptr_t pkt)
{
	if (!pkt) {
		// There was an error receiving the packet, don't bother trying to receive another, just let the connection die
		disconnect_peer(con);
		return;
	}

	network_protocol& protocol = get_protocol(pkt);

	//con->receive_packet(packet::ptr_t(new packet()), boost::protect(boost::bind(&local_node::incoming_packet, this, con, _1, _2)));

	DLOG(INFO) << std::string(id()) << ": Incoming packet, dest=" << std::string(pkt->destination());

	if (con->accepts_ib_traffic() && pkt->content_status() == packet::content_requested)
		protocol.drop_crumb(std::make_pair(pkt->source(), pkt->destination()), con);
	else if (!con->accepts_ib_traffic()) {
		std::vector<oob_peer::ptr_t>::iterator oob_peer_iter = std::find_if(oob_peers_.begin(), oob_peers_.end(), oob_con_ep_cmp(con->remote_endpoint()));
		if (oob_peer_iter != oob_peers_.end())
			(*oob_peer_iter)->reset_timeout();
	}

	snoop(pkt);

	if (pkt->destination() == con->remote_id()) {
		// The destination is equal to the id of the sending peer
		// either he is very confused or snoop came up with a direct reply
		// in any case send the packet directly back at him
		// we can't use dispatch because he might be oob
		con->send(pkt);
		protocol.pickup_crumb(std::make_pair(pkt->destination(), pkt->source()));
		return;
	}

	if (!con->accepts_ib_traffic()) {
		// This packet is from an out-of-band peer, yet we didn't have a reply
		// Return an error
		pkt->source(pkt->destination());
		pkt->destination(con->remote_id());
		pkt->content_status(packet::content_failure);
		pkt->payload(packet::not_found);
		con->send(pkt);
		return;
	}

	if ( pkt->content_status() == packet::content_failure && ::distance(pkt->source(), id()) < ::distance(pkt->source(), con->remote_id()) ) {
		// we got a failure on content which we are closer to than the sender, we must have been deparate so lets continue the desperation

		std::vector<connection::ptr_t>::iterator target = get_sucessor<distance>(pkt->source() + 1, con->remote_id() - 1, pkt->source(), 0);

		if (target != ib_peers_.end()) {
			// we don't want this packet going back through the normal dispatch path
			pkt->mark_direct();

			network_key tmp = pkt->source();
			pkt->source(pkt->destination());
			pkt->destination(tmp);
			pkt->content_status(packet::content_requested);
			pkt->content_size(0);
			(*target)->send(pkt);
			return;
		}
		DLOG(INFO) << "No more peers left for desperation requests";
	}

	if (pkt->content_status() != packet::content_requested) {
		connection::ptr_t con = protocol.pickup_crumb(std::make_pair(pkt->destination(), pkt->source()));
		if (con) {
			con->send(pkt);
			return;
		}
	}

	if ( ::distance(pkt->destination(), id()) < ::distance(pkt->destination(), con->remote_id()) ) {
		// This is from an in-band peer and we are closer to the destination than the sender, go ahead and dispatch normally

		if (!dispatch(pkt) && pkt->content_status() == packet::content_requested) {
			// We are the successor for the requested content but we don't have it, time to go into desperation mode
			// and request the content from all of our peers. If one of them has it they will return it
			// enabling us to complete the request. More imporatantly this is the mechanism by which
			// existing content is migrated to new successor nodes.

			DLOG(INFO) << std::string(id()) << ": Initiating desperation for remote request, content: " << std::string(pkt->destination());

			// we don't want this packet going back through the normal dispatch path
			pkt->mark_direct();

			network_key inner_id(id());
			std::vector<connection::ptr_t>::iterator target;

			for (;;) {
				target = get_sucessor<distance>(pkt->destination() + 1, inner_id, pkt->destination(), 0);

				if (target != ib_peers_.end() && *target == protocol.get_crumb(std::make_pair(pkt->source(), pkt->destination()))) {
					// don't do a desperation request to the peer that originated the request
					inner_id = (*target)->remote_id() - 1;
				}
				else
					break;
			}

			if (target != ib_peers_.end()) {
				(*target)->send(pkt);
			}
			else {
				pkt->to_reply(packet::not_found);
				con->send(pkt);
				protocol.pickup_crumb(std::make_pair(pkt->destination(), pkt->source()));
			}
		}
	}
	else if (pkt->content_status() == packet::content_requested) {
		// peer is closer than us to the destination and we couldn't satisfy it ourselves, we can't foward this
		// so return an error
		pkt->to_reply(packet::not_found);
		con->send(pkt);
	}
}

void local_node::incoming_fragment(connection::ptr_t con, frame_fragment::ptr_t frag, std::size_t payload_size)
{
	if (!frag) {
		// There was an error receiving the packet, don't bother trying to receive another, just let the connection die
		disconnect_peer(con);
		return;
	}

	std::map<protocol_t, network_protocol::ptr_t>::iterator protocol_handler = protocol_handlers_.find(frag->protocol());

	if (protocol_handler == protocol_handlers_.end())
	{
		// TODO: return error unkown protocol
		return;
	}

	if (payload_size) {
		con->receive_payload(frag,
		                     protocol_handler->second->get_fragment_buffer(frag),
		                     boost::protect(boost::bind(&local_node::fragment_received, this, con, _1)));
	}
	else {
		fragment_received(con, frag);
	}

}

void local_node::fragment_received(connection::ptr_t con, frame_fragment::ptr_t frag)
{
	get_protocol(frag).snoop_fragment(con->remote_endpoint(), frag);
}

void local_node::recompute_identity()
{
#ifdef SIMULATION
	public_endpoint_.address(ip::address::from_string("127.0.0.1"));
	boost::uint8_t port[2];
	u16(port, config_.listen_port());
	identity_ = network_key(const_buffer(port, 2));
#else
	int max_count = 0;
	for (std::multiset<ip::address>::iterator it = reported_addresses_.begin(); it != reported_addresses_.end(); ++it) {
		int count = reported_addresses_.count(*it);
		if (count > max_count) {
			public_endpoint_.address(*it);
			max_count = count;
		}
	}
	identity_ = network_key(public_endpoint().address());
#endif
}

int local_node::closer_peers(const network_key& key)
{
	network_key self_dist = ::distance(key, id());
	int closer_count = 0;

	for (std::vector<connection::ptr_t>::iterator it = ib_peers_.begin(); it != ib_peers_.end(); ++it) {
		network_key dist = ::distance(key, (*it)->remote_id());
		if (dist < self_dist)
			closer_count++;
	}
	return closer_count;
}

void local_node::make_connection(ip::tcp::endpoint peer)
{
	if (peer == public_endpoint())
		return;

	for (std::vector<connection::ptr_t>::iterator it = ib_peers_.begin(); it != ib_peers_.end(); ++it)
		if ((*it)->remote_endpoint() == peer)
			return;

	for (std::vector<connection::ptr_t>::iterator it = connecting_peers_.begin(); it != connecting_peers_.end(); ++it)
		if ((*it)->remote_endpoint() == peer && (*it)->accepts_ib_traffic())
			return;

//	for (std::vector<oob_peer::ptr_t>::iterator it = oob_peers_.begin(); it != oob_peers_.end(); ++it)
//		if ((*it)->remote_endpoint() == peer && ((*it)->accepts_ib_traffic() || rtype != connection::ib))
//			return;
//	if (!ib)
//		for (std::vector<connection::weak_ptr_t>::iterator it = oob_peers_.begin(); it != preband_peers_.end(); ++it)
			//if ((*it)->remote_endpoint() == peer && ((*it)->oob_threshold() || !ib))
			//	return;
	connection::connect(*this, peer, connection::ib);
}

#ifdef SIMULATION
void local_node::heal()
{
	std::vector<connection::ptr_t>::iterator sucessor_peer = get_sucessor<reverse_distance>(id()-1, id()+1, id());

	if (sucessor_peer != ib_peers_.end()) {
		heal_timer_.expires_from_now(boost::posix_time::milliseconds(10));
		heal_timer_.async_wait(boost::bind(&local_node::make_connection, boost::ref(*this), sucessor_peer->get()->remote_endpoint()));
		(*sucessor_peer)->disconnect();
		ib_peers_.erase(sucessor_peer);
	}
}
#endif

boost::posix_time::time_duration local_node::base_hunk_lifetime()
{
	using namespace boost::accumulators;

	accumulator_set<double, features<tag::mean, tag::variance> > peer_stats;

	for (std::vector<connection::ptr_t>::iterator it = ib_peers_.begin(); it != ib_peers_.end(); ++it)
		peer_stats((*it)->age().total_seconds());

	return boost::posix_time::seconds(long(mean(peer_stats) + std::sqrt(variance(peer_stats))));
}

void local_node::send_failure(connection::ptr_t con)
{
	// we don't want to route to this peer anymore
	if (con->is_connected()) {
		std::vector<connection::ptr_t>::iterator peer = std::find(ib_peers_.begin(), ib_peers_.end(), con);
		if (peer != ib_peers_.end()) {
			ib_peers_.erase(peer);
			disconnecting_peers_.push_back(con);
		}
	}
}

void local_node::disconnect_peer(connection::ptr_t con)
{
	if (con->is_connected()) {
		std::vector<connection::ptr_t>::iterator peer = std::find(ib_peers_.begin(), ib_peers_.end(), con);
		if (peer != ib_peers_.end()) {
			DLOG(INFO) << std::string(id()) << " Disconnecting in-band peer: " << std::string(con->remote_id());
			if (get_strict_sucessor<reverse_distance>(id() - 1, id() + 1, id()) == peer) {
				// we just lost our reverse successor, ask the new guy if he has a new one for us
				DLOG(INFO) << "Lost RS";
				std::vector<connection::ptr_t>::iterator new_rs = get_strict_sucessor<reverse_distance>(id() - 1, (*peer)->remote_id() + 1, id());

				if (new_rs != ib_peers_.end()) {
					DLOG(INFO) << "Requesting new reverse successor from " << std::string((*new_rs)->remote_id());
					(*new_rs)->request_reverse_successor();
				}
			}

			ib_peers_.erase(peer);
		}

		peer = std::find(connecting_peers_.begin(), connecting_peers_.end(), con);
		if (peer != connecting_peers_.end())
			connecting_peers_.erase(peer);

		peer = std::find(disconnecting_peers_.begin(), disconnecting_peers_.end(), con);
		if (peer != disconnecting_peers_.end())
			disconnecting_peers_.erase(peer);

		std::vector<oob_peer::ptr_t>::iterator opeer = std::find(oob_peers_.begin(), oob_peers_.end(), con);
		if (opeer != oob_peers_.end())
			oob_peers_.erase(opeer);

		con->disconnect();
	}
}

void local_node::update_threshold_stats()
{
	min_oob_threshold_ = std::numeric_limits<std::size_t>::max();
	max_oob_threshold_ = std::numeric_limits<std::size_t>::min();

	for (std::vector<connection::ptr_t>::iterator peer = ib_peers_.begin(); peer != ib_peers_.end(); ++peer) {
		if ((*peer)->oob_threshold() < min_oob_threshold_)
			min_oob_threshold_ = ((*peer)->oob_threshold());
		if ((*peer)->oob_threshold() > max_oob_threshold_)
			max_oob_threshold_ = ((*peer)->oob_threshold());
	}
}
