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

#include <glog/logging.h>

#include "peer_cache.hpp"
#include <boost/lexical_cast.hpp>
#include <fstream>
#include <string>
#include <boost/random.hpp>

network_peer_cache peer_cache;

network_peer_cache::network_peer_cache()
	: getp_(0)
{
	std::ifstream cache_file("peer_cache");

	while (cache_file && !cache_file.eof()) {
		std::string ip;
		cache_file >> ip;
		std::string::size_type separator = ip.find(':');

		if (separator == std::string::npos)
			continue;

		boost::asio::ip::address_v4 address = boost::asio::ip::address_v4::from_string(ip.substr(0, separator));

		DLOG(INFO) << "Loading cached peer: " << address.to_string() << ':' << ip.substr(separator + 1);

		peers_.push_back( ip::tcp::endpoint( address, boost::lexical_cast<unsigned short>( ip.substr(separator + 1) ) ) );
	}

}

ip::tcp::endpoint network_peer_cache::get_peer()
{
#ifdef SIMULATION
	if (!peers_.size())
		return ip::tcp::endpoint();
	static boost::mt19937 rng;
	getp_ = boost::variate_generator<boost::mt19937&, boost::uniform_int<> >(rng, boost::uniform_int<>(0, peers_.size() - 1))();
#else
	if (getp_ >= peers_.size()) {
		getp_ = 0;
		return ip::tcp::endpoint();
	}
#endif
	return peers_[getp_++];
}

void network_peer_cache::fail_peer(ip::tcp::endpoint peer)
{
	std::vector<ip::tcp::endpoint>::iterator p = std::find(peers_.begin(), peers_.end(), peer);

	if (p != peers_.end())
		peers_.erase(p);
}

void network_peer_cache::add_peer(ip::tcp::endpoint peer)
{
	peers_.push_back(peer);
}

void network_peer_cache::flush()
{
	std::ofstream cache_file("peer_cache");

	for (std::vector<ip::tcp::endpoint>::iterator it = peers_.begin(); it != peers_.end(); ++it)
		cache_file << it->address().to_string() << ':' << it->port();
}