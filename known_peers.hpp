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
#include "authority.hpp"
#include <db_cxx.h>
#include <openssl/rsa.h>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <boost/cstdint.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/deadline_timer.hpp>
#include <map>

class known_peers
{
	friend class iterator;

	class known_peer
	{
	public:
		static const int days = 7;

		struct packed;

		explicit known_peer(packed* data);

		known_peer() : pubkey_(NULL), total_sent_(0), total_received_(0)
		{

		}

		void sent_content(std::size_t bytes) { total_sent_ += bytes; sent_today_ += bytes; }
		void received_content(std::size_t bytes) { total_received_ += bytes; received_today_ += bytes; }

		boost::uint64_t total_sent()
		{
			return total_sent_;
		}

		boost::uint64_t total_received()
		{
			return total_received_;
		}

		boost::posix_time::ptime get_credited(boost::posix_time::ptime now, boost::uint64_t average_bytes_sent_per_day) const
		{
			using boost::posix_time::time_duration;

			return std::max(credited_, now)
			       + time_duration(time_duration::hour_type(double(received_today_) / double(average_bytes_sent_per_day) * 24),
			                       time_duration::min_type((double(received_today_) / double(average_bytes_sent_per_day) * (24 * 3600))) % 3600,
			                       0, 0);
		}

		boost::posix_time::ptime rollover_time() { return rollover_; }
		void do_rollover(packed* data, boost::posix_time::ptime now, boost::uint64_t average_bytes_sent_per_day);

	private:
		boost::asio::ip::tcp::endpoint endpoint_;
		RSA* pubkey_;
		boost::posix_time::ptime credited_,rollover_;
		boost::uint64_t total_sent_, total_received_;
		boost::uint64_t sent_today_, received_today_;
	};

	typedef std::map<network_key, known_peer> peers_t;

public:
	struct credit_type
	{
		credit_type() {}
		credit_type(network_key r, boost::posix_time::ptime e) : recipient(r), expires(e) {}

		network_key recipient;
		boost::posix_time::ptime expires;
		const_buffer signature;
		heap_buffer signature_storage;
	};

	class iterator
	{
		friend class known_peers;
	public:
		iterator& operator++()
		{
			sorted_peers_.pop_back();
			return *this;
		}

		const network_key& recipient()
		{
			return sorted_peers_.back()->first;
		}

		boost::posix_time::ptime expires()
		{
			return sorted_peers_.back()->second.get_credited(boost::posix_time::second_clock::universal_time(), peers_.average_bytes_sent_per_day());
		}

		const_buffer signature(const_buffer packed_credit)
		{
			return peers_.signer_.sign(packed_credit, mutable_buffer(&sig_buf_[0], sig_buf_.size()));
		}

		bool operator!=(const iterator& other)
		{
			return !sorted_peers_.empty() || !other.sorted_peers_.empty();
		}

	private:
		explicit iterator(const known_peers& peers) : peers_(peers) {}
		iterator(const known_peers& peers, const network_key& target);

		const known_peers& peers_;
		std::vector<peers_t::const_iterator> sorted_peers_;
		std::vector<boost::uint8_t> sig_buf_;
	};

	known_peers(boost::asio::io_service& io_service, const std::string& db_path, const author& signer);
	~known_peers() { db_.close(0); }

	authority get_creditor(const network_key& id) const
	{
		return authority(signer_);
	}

	iterator begin(const network_key& issuer, const network_key& target) const
	{
		return iterator(*this, target);
	}

	iterator end() const { return iterator(*this); }

	void sent_content(const network_key& id, std::size_t bytes);
	void received_content(const network_key& id, std::size_t bytes);
//	std::vector<credit_type> best_credits(const network_key& id, unsigned max_returned = 50);

	boost::uint64_t average_bytes_sent_per_day() const
	{
		if (peers_.size() == 0) return 0;
		return total_sent_ / peers_.size() / known_peer::days;
	}

private:
//	std::pair<derived_t::iterator, persistent_t::iterator> get_record(const network_key& id);
	peers_t::iterator new_peer(network_key id);
	peers_t::iterator transfered_content(network_key id, std::size_t bytes, unsigned data_offset);

	int closer_credits(const network_key& peer, const network_key& credit);

	void rollover(const boost::system::error_code& error);

	boost::uint64_t total_sent_;
	boost::uint64_t total_received_;
	boost::posix_time::ptime max_credited_;
	peers_t peers_;
	Db db_;
	boost::asio::deadline_timer next_rollover_;
	const author& signer_;
};

#endif
