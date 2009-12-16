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
#include "protocols/user_content.hpp"
#include "config.hpp"
#include "peer_cache.hpp"
#include "packet.hpp"
#include "connection.hpp"
#include <boost/bind/protect.hpp>
#include <boost/accumulators/accumulators.hpp>
#include <boost/accumulators/statistics/mean.hpp>
#include <boost/accumulators/statistics/variance.hpp>
#include <limits>

class user_content;

#ifdef SIMULATION
#include "simulator.hpp"
#endif

local_node::local_node(boost::asio::io_service& io_service, client_config& config)
	: config_(config), acceptor_(io_service, ip::tcp::endpoint(ip::address::from_string(config.listen_ip()), config.listen_port())),
	  public_endpoint_(acceptor_.local_endpoint()), created_(boost::posix_time::second_clock::universal_time()), stored_size_(0)
	  
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
					// we did, let him know about this new peer, this new peer is likely to be of interest to him as a reverse successor
					(*old_successor)->send_reverse_successor();
				}
			}

			// update the closer peers count for cache policy tracking
			for (std::list<stored_hunk>::iterator hunk = stored_hunks_.begin(); hunk != stored_hunks_.end(); ++hunk) {
				if (!hunk->local_requested && ::distance(hunk->id, con->remote_id()) < ::distance(hunk->id, id()))
					hunk->closer_peers++;
			}
		}
		else {
			oob_peers_.push_back(oob_peer::create(*this, con));
		}
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

std::vector<protocol_t> local_node::supported_protocols() const
{
	std::vector<protocol_t> protocols;

	for (std::map<protocol_t, network_protocol::ptr_t>::const_iterator protocol = protocol_handlers_.begin();
		protocol != protocol_handlers_.end();
		++protocol)
	{
		// don't count protocols if they are the basic user content handler
		// we don't really "know" these protocols, the handler is only there
		// so we can oblivisiously pass around requests and detached content
		if (typeid(protocol->second.get()) != typeid(user_content))
			protocols.push_back(protocol->second->id());
	}

	return protocols;
}

network_protocol::ptr_t local_node::validate_protocol(protocol_t protocol)
{
	std::map<protocol_t, network_protocol::ptr_t>::iterator protocol_handler = protocol_handlers_.find(protocol);

	if (protocol_handler == protocol_handlers_.end())
	{
		if (is_user_content(protocol)) {
			network_protocol::ptr_t new_protocol(new user_content(*this, protocol));
			protocol_handler = protocol_handlers_.insert(std::make_pair(protocol, new_protocol)).first;
		}
		else
			return network_protocol::ptr_t();
	}

	return protocol_handler->second;
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
	std::size_t content_size = pkt->payload()->content_size();

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
			pkt->to_reply(packet::content_failure);

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

	network_protocol::ptr_t protocol_handler = validate_protocol(pkt->protocol());

	if (!protocol_handler)
	{
		receive_failure(con);
		return;
	}

	protocol_handler->receive_payload(con, pkt, payload_size);
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
		protocol.to_content_location_failure(pkt);
		con->send(pkt);
		return;
	}

	if ( pkt->content_status() == packet::content_failure && ::distance(pkt->source(), id()) < ::distance(pkt->source(), con->remote_id()) ) {
		// we got a failure on content which we are closer to than the sender, we must have been deparate so lets continue the desperation

		std::vector<connection::ptr_t>::iterator target = get_sucessor<distance>(pkt->source() + 1, con->remote_id() - 1, pkt->source(), 0);

		if (target != ib_peers_.end()) {
			// we don't want this packet going back through the normal dispatch path
			pkt->mark_direct();

			protocol.request_from_location_failure(pkt);
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
				protocol.to_content_location_failure(pkt);
				con->send(pkt);
				protocol.pickup_crumb(std::make_pair(pkt->destination(), pkt->source()));
			}
		}
	}
	else if (pkt->content_status() == packet::content_requested) {
		// peer is closer than us to the destination and we couldn't satisfy it ourselves, we can't foward this
		// so return an error
		protocol.to_content_location_failure(pkt);
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

	network_protocol::ptr_t protocol_handler = validate_protocol(frag->protocol());

	if (!protocol_handler) {
		receive_failure(con);
		return;
	}

	boost::dynamic_pointer_cast<user_content>(protocol_handler)->incoming_fragment(con, frag, payload_size);
}

void local_node::fragment_received(connection::ptr_t con, frame_fragment::ptr_t frag)
{
	boost::dynamic_pointer_cast<user_content>(validate_protocol(frag->protocol()))->snoop_fragment(con->remote_endpoint(), frag);
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

			// update the closer peers count for cache policy tracking
			for (std::list<stored_hunk>::iterator hunk = stored_hunks_.begin(); hunk != stored_hunks_.end(); ++hunk) {
				if (!hunk->local_requested && ::distance(hunk->id, con->remote_id()) < ::distance(hunk->id, id()))
					hunk->closer_peers--;
			}

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

			// update the closer peers count for cache policy tracking
			for (std::list<stored_hunk>::iterator hunk = stored_hunks_.begin(); hunk != stored_hunks_.end(); ++hunk) {
				if (!hunk->local_requested && ::distance(hunk->id, con->remote_id()) < ::distance(hunk->id, id()))
					hunk->closer_peers--;
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
	std::size_t sum = 0;

	for (std::vector<connection::ptr_t>::iterator peer = ib_peers_.begin(); peer != ib_peers_.end(); ++peer) {
		if ((*peer)->oob_threshold() < min_oob_threshold_)
			min_oob_threshold_ = ((*peer)->oob_threshold());
		if ((*peer)->oob_threshold() > max_oob_threshold_)
			max_oob_threshold_ = ((*peer)->oob_threshold());
		sum += ((*peer)->oob_threshold());
	}

	avg_oob_threshold_ = sum / ib_peers_.size();
}

struct hunk_desc_cmp
{
	hunk_desc_cmp() : now(boost::posix_time::second_clock::universal_time()) {}

	bool operator()(const stored_hunk& l, const stored_hunk& r) const
	{
		return staleness(now - l.last_access, l.closer_peers) > staleness(now - r.last_access, r.closer_peers);
	}

	bool operator()(const stored_hunk& l, double r) const
	{
		return staleness(now - l.last_access, l.closer_peers) > r;
	}

	double staleness(boost::posix_time::time_duration age, int closer_peers) const
	{
		return age.total_seconds() * std::exp(double(closer_peers));
	}

	const boost::posix_time::ptime now;
};

hunk_descriptor_t local_node::cache_local_request(protocol_t pid, network_key id, std::size_t size)
{
	stored_hunks_t::iterator hunk = stored_hunks_.begin();
	for (; hunk != stored_hunks_.end(); ++hunk) {
		if (hunk->protocol == pid && hunk->id == id) {
			hunk->local_requested = true;
			hunk->closer_peers = 0;
			return stored_hunks_.end();
		}
	}

	try_prune_cache(size, 0, boost::posix_time::time_duration(0, 0, 0, 0));
	stored_hunks_.push_back(stored_hunk(pid, id, size, 0, true));
	stored_size_ += size;
	return --stored_hunks_.end();
}

hunk_descriptor_t local_node::cache_remote_request(protocol_t pid, network_key id, std::size_t size, boost::posix_time::time_duration request_delta)
{
	// hunk is larger than our average oob threshold, we will never cache such a hunk
	// for remote requests, shouldn't be needed since we should not be seeing attached data
	// that exceeds our threshold
	//if (size > average_oob_threshold())
	//	return stored_hunks_.end();

	int closer = closer_peers(id);

	if (!try_prune_cache(size, closer, request_delta))
		return stored_hunks_.end();

	stored_hunks_.push_back(stored_hunk(pid, id, size, closer, false));
	stored_size_ += size;
	return --stored_hunks_.end();
}

hunk_descriptor_t local_node::cache_store(protocol_t pid, network_key id, std::size_t size)
{
	int closer = closer_peers(id);

	if (closer < 2) {
		try_prune_cache(size, closer, boost::posix_time::time_duration(0, 0, 0, 0));
		stored_hunks_.push_back(stored_hunk(pid, id, size, closer, false));
		stored_size_ += size;
		return --stored_hunks_.end();
	}

	return stored_hunks_.end();
}

bool local_node::try_prune_cache(std::size_t size, int closer_peers, boost::posix_time::time_duration age)
{
	// only bother looking for hunks to prune if we don't already have enough free space
	if (stored_size_ + size > config_.target_store_size()) {
		hunk_desc_cmp compare;
		boost::uint64_t needed_bytes_ = size - (config_.target_store_size() - stored_size_);
		double new_hunk_staleness = compare.staleness(age, closer_peers);
		std::vector<stored_hunks_t::iterator> to_be_pruned;

		// first we need to sort the list in decending order according to "staleness"
		stored_hunks_.sort(compare);

		// start at the begining of the list and work through it until eiher:
		// 1. The current hunk has a lower staleness than the candidate
		// 2. Pruning all hunks up to the current will free up enough space for the candidate
		for (stored_hunks_t::iterator hunk = stored_hunks_.begin(); hunk != stored_hunks_.end() && compare(*hunk, new_hunk_staleness); ++hunk) {
			// skip any hunks which have been stored for less than one hour multiplied by e^(-closer_peers)
			// this is a minimum requirement to maintain network integrity
			if ((compare.now - hunk->stored).total_seconds() < boost::posix_time::hours(1).total_seconds() * std::exp(double(-closer_peers)))
				continue;

			to_be_pruned.push_back(hunk);
			if (needed_bytes_ <= hunk->size) {
				// That's it, we've got enough bytes, now prune the hunks to free the space
				for (std::vector<stored_hunks_t::iterator>::iterator pruned = to_be_pruned.begin(); pruned != to_be_pruned.end(); ++pruned) {
					get_protocol((*pruned)->protocol).prune_hunk((*pruned)->id);
					stored_hunks_.erase(*pruned);
				}

				return true;
			}
			needed_bytes_ -= hunk->size;
			stored_size_ -= hunk->size;
		}

		// if we get here it means we failed to free up enough space :(
		return false;
	}

	return true;
}

hunk_descriptor_t local_node::load_existing_hunk(protocol_t pid, network_key id, std::size_t size)
{
	stored_hunks_.push_back(stored_hunk(pid, id, size, closer_peers(id), false));
	stored_size_ += size;
	return --stored_hunks_.end();
}
