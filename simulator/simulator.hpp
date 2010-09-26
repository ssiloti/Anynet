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

#ifndef NETWORK_SIMULATOR_HPP
#define NETWORK_SIMULATOR_HPP

#include <glog/logging.h>

#include "traffic_generator.hpp"
#include <boost/shared_ptr.hpp>
#include <boost/random.hpp>
#include <vector>
#include <cmath>

class network_simulator
{
public:
	network_simulator();

	int node_lifetime()                     { return time_ + int(node_lifetime_()); }

	int insert_non_authoritative_interval() { return time_ + int(insert_non_authoritative_interval_()); }
	int get_non_authoritative_interval()    { return time_ + int(get_non_authoritative_interval_()); }

	void new_non_authoritative(network_key id) { assert(!node_created(id)); non_authoritative_hunks_.queue.push_back(id); }
	network_key get_non_authoritative();
	void stored_non_authoritative_hunk(network_key id);

	void failed_non_authoritative_retrieval() { failed_retrievals_.push_back(0); }
	void sucessful_retrieval()                { ++sucessful_retrievals_; }

	void tick();

	void run() { io_service.run(); }

	void begin_query()    { ++outstanding_queries; DLOG(INFO) << "Begin Q " << outstanding_queries; }
	void complete_query() { assert(outstanding_queries); --outstanding_queries; DLOG(INFO) << "End Q " << outstanding_queries; }

	void kill_node(boost::shared_ptr<traffic_generator> node)
	{
		client_hitlist_.push_back(std::find(clients.begin(), clients.end(), node));
	}

	bool node_created(const network_key& id);

	void verify_reverse_successor(const network_key& node, const network_key& rsuccessor);

private:
	typedef boost::variate_generator<boost::mt19937&, boost::lognormal_distribution<> > interval_variant_t;

	struct hunk_stats
	{
		hunk_stats() : storing_nodes(1) {}
		int storing_nodes;
	};

	struct hunk_index
	{
		std::map<network_key, hunk_stats> active;
		std::vector<network_key> queue;
	};

	void tick(const boost::system::error_code& error);

	boost::mt19937 rng_;
	interval_variant_t node_lifetime_;
	interval_variant_t insert_non_authoritative_interval_;
	interval_variant_t get_non_authoritative_interval_;
	hunk_index non_authoritative_hunks_;

	std::vector<int> failed_retrievals_;
	int sucessful_retrievals_;

	int time_;
	int outstanding_queries;
	boost::asio::io_service io_service;
	std::vector<boost::shared_ptr<traffic_generator> > clients;
	std::vector<std::vector<boost::shared_ptr<traffic_generator> >::iterator> client_hitlist_;
	boost::asio::deadline_timer tick_timer_;
	std::vector<boost::shared_ptr<traffic_generator> >::iterator next_heal_client_;
	int heal_count_;
};

extern network_simulator sim;

#endif