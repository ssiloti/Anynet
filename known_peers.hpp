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

#ifndef TRAFFIC_STATS_HPP
#define TRAFFIC_STATS_HPP

#include "key.hpp"
#include <db_cxx.h>
#include <openssl/rsa.h>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <boost/cstdint.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <map>

class known_peers
{
	class known_peer
	{
	public:
		static const int days = 7;

		struct packed;

		explicit known_peer(packed* data);

		explicit known_peer(boost::posix_time::time_duration r) : rollover_(r), pubkey_(NULL), total_sent_(0), total_received_(0)
		{

		}

		void sent_content(std::size_t bytes) { total_sent_ += bytes; }
		void received_content(std::size_t bytes) { total_received_ += bytes; }

		boost::uint64_t total_sent()
		{
			return total_sent_;
		}

		boost::uint64_t total_received()
		{
			return total_received_;
		}

		boost::posix_time::time_duration rollover_time() { return rollover_; }
		void rollover(const network_key& id);

	private:
		boost::asio::ip::tcp::endpoint endpoint_;
		RSA* pubkey_;
		boost::posix_time::time_duration rollover_;
		boost::uint64_t total_sent_, total_received_;
	};

	typedef std::map<network_key, known_peer> peers_t;

public:
	known_peers(const std::string& db_path);
	~known_peers() { db_.close(0); }

	void sent_content(const network_key& id, std::size_t bytes);
	void received_content(const network_key& id, std::size_t bytes);
	std::vector<std::pair<network_key, boost::uint64_t> > best_credits(const network_key& id, unsigned int max_returned = 50);

private:
//	std::pair<derived_t::iterator, persistent_t::iterator> get_record(const network_key& id);
	peers_t::iterator new_peer(network_key id);
	peers_t::iterator transfered_content(network_key id, std::size_t bytes, unsigned data_offset);
	void rollover(const network_key& id);

	boost::uint64_t total_sent_;
	boost::uint64_t total_received_;
	peers_t peers_;
	Db db_;
};

#endif
