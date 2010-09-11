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

#include "simulator.hpp"
#include "traffic_generator.hpp"
#include "signature_schemes/non_authoritative.hpp"
#include "node.hpp"
#include <boost/smart_ptr.hpp>
#include <vector>

const static int target_node_count = 10;

network_simulator::network_simulator() : node_lifetime_(rng_, boost::lognormal_distribution<>(600, 200)),
	  insert_non_authoritative_interval_(rng_, boost::lognormal_distribution<>(200, 10)),
	  get_non_authoritative_interval_(rng_, boost::lognormal_distribution<>(10, 1)),
	  time_(0), outstanding_queries(0), tick_timer_(io_service)
{
	tick(boost::system::error_code());
}

void network_simulator::stored_non_authoritative_hunk(network_key id)
{
	std::map<network_key, hunk_stats>::iterator hunk = non_authoritative_hunks_.active.find(id);
	if (hunk != non_authoritative_hunks_.active.end())
		++hunk->second.storing_nodes;
}

void network_simulator::tick(const boost::system::error_code& error)
{
	if (!outstanding_queries)
	{
		/*
		for (std::vector<boost::shared_ptr<traffic_generator> >::iterator client = clients.begin(); client != clients.end(); ++client)
			if ((*client))
				verify_reverse_successor((*client)->node_.id(), (*client)->node_.self_predecessor());*/

		if (clients.size() < target_node_count) {
			clients.push_back(boost::shared_ptr<traffic_generator>(new traffic_generator(io_service, clients.size())));
		}
		else {
			for (std::vector<boost::shared_ptr<traffic_generator> >::iterator client = clients.begin(); client != clients.end(); ++client) {
				if (!*client)
					client->reset(new traffic_generator(io_service, std::distance(clients.begin(), client)));
				(*client)->tick(time_);
			}

			for (std::vector<network_key>::iterator it = non_authoritative_hunks_.queue.begin(); it != non_authoritative_hunks_.queue.end(); ++it) {
				non_authoritative_hunks_.active.insert(std::make_pair(*it, hunk_stats()));
			}

			non_authoritative_hunks_.queue.clear();

			++time_;
		}

		for (std::vector<std::vector<boost::shared_ptr<traffic_generator> >::iterator>::iterator it = client_hitlist_.begin(); it != client_hitlist_.end(); ++it) {
			(*it)->reset();
		}

		client_hitlist_.clear();
	}
	tick_timer_.expires_from_now(boost::posix_time::milliseconds(200));
	tick_timer_.async_wait(boost::bind(&network_simulator::tick, this, placeholders::error));
	google::FlushLogFiles(google::INFO);
}

network_simulator sim;

int main(int argc, char* argv[])
{
//	FLAGS_logtostderr = true;
	FLAGS_log_dir = ".";
	google::InitGoogleLogging(argv[0]);
	sim.run();
	return 0;
}

bool network_simulator::node_created(const network_key& id)
{
	for (std::vector<boost::shared_ptr<traffic_generator> >::iterator client = clients.begin(); client != clients.end(); ++client) {
		if (*client) {
			if ((*client)->node_.id() == id)
				return true;
		}
	}
	return false;
}

void network_simulator::verify_reverse_successor(const network_key& node, const network_key& rsuccessor)
{
	for (std::vector<boost::shared_ptr<traffic_generator> >::iterator client = clients.begin(); client != clients.end(); ++client) {
		if ((*client) && (*client)->node_.id() != node && reverse_distance(node, (*client)->node_.id()) < reverse_distance(node, rsuccessor)) {
			google::FlushLogFiles(google::INFO);
			assert(false);
		}
	}
}
