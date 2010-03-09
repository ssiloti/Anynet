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

#ifndef NODE_HPP
#define NODE_HPP

#include <glog/logging.h>

#include "known_peers.hpp"
#include "connection.hpp"
#include "protocol.hpp"
#include "config.hpp"
#include <boost/asio/deadline_timer.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/function.hpp>
#include <vector>
#include <map>
#include <set>

class local_node
{
#ifdef SIMULATION
	friend class traffic_generator;
#endif

public:
	struct oob_peer : boost::enable_shared_from_this<oob_peer>
	{
		typedef boost::shared_ptr<oob_peer> ptr_t;

		static ptr_t create(local_node& node, connection::ptr_t con)
		{
			ptr_t n(new oob_peer(node, con));
			n->reset_timeout();
			return n;
		}

		~oob_peer()
		{
			DLOG(INFO) << "Destroyed oob peer " << this;
			timeout.cancel();
		}

		void reset_timeout()
		{
			timeout.expires_from_now(boost::posix_time::seconds(60));
			timeout.async_wait(boost::bind(&oob_peer::disconnect, shared_from_this(), placeholders::error));
		}

		void disconnect(const boost::system::error_code& error)
		{
			if (!error) {
				if (!con->is_transfer_outstanding())
					node.disconnect_peer(con);
				else
					reset_timeout();
			}
		}

		connection::ptr_t con;
		local_node& node;
		boost::asio::deadline_timer timeout;

	private:
		oob_peer(local_node& node, connection::ptr_t con) : con(con), node(node), timeout(node.io_service())
		{
		}
	};
	friend struct oob_peer;

	local_node(boost::asio::io_service& io_service, client_config& config);
	~local_node();

	// getters
	boost::asio::io_service& io_service() { return acceptor_.get_io_service(); }
	const network_key& id() const { return identity_; }
	const ip::tcp::endpoint& public_endpoint() const { return public_endpoint_; }
	bool is_v4() const { return public_endpoint_.address().is_v4(); }
	bool is_v6() const { return public_endpoint_.address().is_v6(); }
	std::vector<connection::ptr_t>::size_type connection_count() { return ib_peers_.size(); }
	const client_config& config() const { return config_; }
	boost::posix_time::time_duration base_hunk_lifetime();
	boost::posix_time::time_duration age() const { return boost::posix_time::second_clock::universal_time() - created_; }
	std::size_t average_oob_threshold() const { return avg_oob_threshold_; }
	std::vector<protocol_t> supported_protocols() const;

	// connections
	void make_connection(ip::tcp::endpoint peer);
	void connection_in_progress(connection::ptr_t con) { connecting_peers_.push_back(con); }
	void register_connection(connection::ptr_t con);

	// protocols
	template <typename P>
	P& protocol()
	{
		return *boost::static_pointer_cast<P>( protocol_handlers_.find(P::protocol_id)->second );
	}
	network_protocol& get_protocol(packet::ptr_t pkt) { return get_protocol(pkt->protocol()); }
	network_protocol& get_protocol(frame_fragment::ptr_t frag) { return get_protocol(frag->protocol()); }
	network_protocol& get_protocol(protocol_t pid) { return *protocol_handlers_.find(pid)->second; }

	bool register_protocol_handler(protocol_t id, network_protocol::ptr_t proto)
	{
		return protocol_handlers_.insert(std::make_pair(id, proto)).second;
	}

	// successors
	ip::tcp::endpoint sucessor_endpoint(const network_key& key);
	ip::tcp::endpoint reverse_sucessor_endpoint(const network_key& key);
	network_key self_reverse_sucessor();
	int closer_peers(const network_key& key);

	// requests
	void direct_request(ip::tcp::endpoint peer, frame_fragment::ptr_t frag);
	connection::ptr_t local_request(packet::ptr_t pkt);
	connection::ptr_t local_request(packet::ptr_t pkt, const network_key& inner_id);
	connection::ptr_t dispatch(packet::ptr_t pkt);
	connection::ptr_t dispatch(packet::ptr_t pkt, const network_key& inner_id, bool local_request = false);

	// content carrying message handling
	// incoming_* is to notify the local node that a message header has just been received
	// the node is expected to return a buffer into which the payload data will be written
	void incoming_packet(connection::ptr_t con, packet::ptr_t pkt, std::size_t payload_size);
	void packet_received(connection::ptr_t con, packet::ptr_t pkt);

	void incoming_fragment(connection::ptr_t con, frame_fragment::ptr_t frag, std::size_t payload_size);
	void fragment_received(connection::ptr_t con, frame_fragment::ptr_t frag);

	// failures
	void send_failure(connection::ptr_t con);
	void receive_failure(connection::ptr_t con) { disconnect_peer(con); }

	// cache policy
	hunk_descriptor_t cache_local_request(protocol_t pid, network_key id, std::size_t size);
	hunk_descriptor_t cache_store(protocol_t pid, network_key id, std::size_t size);
	hunk_descriptor_t cache_remote_request(protocol_t pid, network_key id, std::size_t size, boost::posix_time::time_duration request_delta);
	hunk_descriptor_t load_existing_hunk(protocol_t pid, network_key id, std::size_t size);
	hunk_descriptor_t not_a_hunk() { return stored_hunks_.end(); }

	// credit accounting
	void sent_content(const network_key& id, std::size_t bytes) { traffic_stats_.sent_content(id, bytes); }

	rolling_stats sources_per_hunk;

	boost::asio::ssl::context context;

private:
	void bootstrap();
	void recompute_identity();
	void snoop(packet::ptr_t pkt);
	void disconnect_peer(connection::ptr_t con);
	void update_threshold_stats();

	bool is_user_content(protocol_t p)    const { return (p >> 6) == 0; }
	bool is_network_control(protocol_t p) const { return (p >> 6) == 1; }
	network_protocol::ptr_t validate_protocol(protocol_t protocol);

	bool try_prune_cache(std::size_t size, int closer_peers, boost::posix_time::time_duration age);

	// successors
	std::vector<connection::ptr_t>::iterator sucessor(const network_key& key, const network_key& inner_id, std::size_t content_size = 0);

	template <network_key dist_fn(const network_key& src, const network_key& dest)>
	std::vector<connection::ptr_t>::iterator get_sucessor(const network_key& outer_id, const network_key& inner_id, const network_key& key, std::size_t content_size = 0);

	// strict successor doesn't take ancillary factors into account, it will always return the closest node in terms of key distance
	template <network_key dist_fn(const network_key& src, const network_key& dest)>
	std::vector<connection::ptr_t>::iterator get_strict_sucessor(const network_key& outer_id, const network_key& inner_id, const network_key& key, std::size_t content_size = 0);

	void generate_cert();

	client_config&           config_;
	ip::tcp::acceptor        acceptor_;
	boost::posix_time::ptime created_;

	std::multiset<ip::address> reported_addresses_;
	ip::tcp::endpoint          public_endpoint_;
	network_key                identity_;

	std::vector<connection::ptr_t> ib_peers_;
	std::vector<oob_peer::ptr_t>   oob_peers_;
	std::vector<connection::ptr_t> connecting_peers_;
	std::vector<connection::ptr_t> disconnecting_peers_;

	std::map<protocol_t, network_protocol::ptr_t> protocol_handlers_;

	std::size_t min_oob_threshold_, max_oob_threshold_, avg_oob_threshold_;

	// cache policy
	stored_hunks_t stored_hunks_;
	boost::uint64_t stored_size_;

	RSA* client_key_;

	known_peers traffic_stats_;
};

inline bool operator==(local_node::oob_peer::ptr_t l, connection::ptr_t r) { return r == l->con; }

#endif
