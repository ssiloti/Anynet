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

#include "traffic_generator.hpp"
#include "simulator.hpp"
#include <protocols/user_content/non_authoritative.hpp>
#include <protocols/indirect_credit.hpp>
#include <peer_cache.hpp>
#include <boost/bind/protect.hpp>

traffic_generator::traffic_generator(boost::asio::io_service& io_service, int id)
	: config_(id)
	, node_(io_service, config_)
	, next_non_authoritative_insert_(sim.insert_non_authoritative_interval())
	, next_non_authoritative_get_(sim.get_non_authoritative_interval())
	, death_(sim.node_lifetime())
{
	peer_cache.add_peer(ip::tcp::endpoint(ip::address::from_string("127.0.0.1"), config_.listen_port()));
	non_authoritative::create(node_);
	indirect_credit::create(node_);
}

void traffic_generator::tick(int time)
{
	//if (time == death_) {
	//	sim.kill_node(shared_from_this());
	//	return;
	//}
	if (time == next_non_authoritative_insert_) {
		non_authoritative& non_auth = node_.protocol<non_authoritative>();
		std::stringstream content;
		content << config_.listen_port() << time;
		non_authoritative::insert_buffer payload = non_auth.get_insertion_buffer(content.str().size());
		std::memcpy(buffer_cast<char*>(payload.get()), content.str().data(), content.str().size());
		content_identifier cid(non_auth.insert_hunk(payload));
		next_non_authoritative_insert_ = sim.insert_non_authoritative_interval();
		DLOG(INFO) << "New stored non-authoritative hunk (" << content.str() << ") " << std::string(cid.publisher);
	}
	if (time == next_non_authoritative_get_) {
		network_key hunk_id = sim.get_non_authoritative();
		if (hunk_id != key_max) {
			sim.begin_query();
			DLOG(INFO) << "Node id=" << std::string(node_.id()) << " Requesting non-authoritative hunk id=" << std::string(hunk_id);
			non_authoritative& non_auth = node_.protocol<non_authoritative>();
			non_auth.retrieve_hunk(hunk_id, boost::protect(boost::bind(&traffic_generator::hunk_received, this, _1)));
		}
		next_non_authoritative_get_ = sim.get_non_authoritative_interval();
	}
}

void traffic_generator::hunk_received(const_payload_buffer_ptr content)
{
	if (content) {
		DLOG(INFO) << "Node id=" << std::string(node_.id()) << " Successfully retrieved non-authoritative hunk id=" << std::string(network_key(content->get()));
		sim.sucessful_retrieval();
	}
	else {
		DLOG(INFO) << std::string(node_.id()) << ": Failed to retrieve non-authoritative hunk";
		google::FlushLogFiles(google::INFO);
		sim.failed_non_authoritative_retrieval();
	}
	google::FlushLogFiles(google::INFO);
	sim.complete_query();
}
