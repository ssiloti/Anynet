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

#include "known_peers.hpp"
#include <boost/tuple/tuple.hpp>
#include <cstdlib>

namespace ip = boost::asio::ip;

struct known_peers::known_peer::packed
{
	boost::uint64_t sent[days];
	boost::uint64_t received[days];
	boost::posix_time::ptime rollover, credited;
	ip::tcp::endpoint ip;
	boost::uint16_t key_length;
	boost::uint8_t pubkey[1];
};

known_peers::known_peer::known_peer(packed* data)
	: total_sent_(0), total_received_(0), pubkey_(NULL), endpoint_(data->ip), rollover_(data->rollover)
{
	boost::posix_time::time_duration since_rollover = boost::posix_time::second_clock::universal_time() - rollover_;
	int backed_rollovers = std::min(since_rollover.hours() / 24, long(days));

	for (int rollovers = 0; rollovers < backed_rollovers; ++rollovers) {
		data->sent[rollovers] = data->sent[days - backed_rollovers + rollovers];
		data->received[rollovers] = data->received[days - backed_rollovers + rollovers];
	}

	for (int i = days - backed_rollovers; i < days; ++i) {
		data->sent[i] = 0;
		data->received[i] = 0;
	}

	for (int day = 0; day < days; ++day) {
		total_sent_ += data->sent[day];
		total_received_ += data->received[day];
	}

	if (data->key_length) {
		const unsigned char* key_ptr = data->pubkey;
		pubkey_ = d2i_RSAPublicKey(&pubkey_, &key_ptr, data->key_length);
	}
}

void known_peers::known_peer::do_rollover(packed* data, boost::posix_time::ptime now, boost::uint64_t average_bytes_sent_per_day)
{
	using boost::posix_time::time_duration;

	time_duration since_rollover = now - data->rollover;
	int backed_rollovers = std::min(since_rollover.hours() / 24, long(days));

	total_sent_ = total_received_ = sent_today_ = received_today_ = 0;

	for (int rollovers = 0; rollovers < backed_rollovers; ++rollovers) {
		data->sent[rollovers] = data->sent[days - backed_rollovers + rollovers];
		data->received[rollovers] = data->received[days - backed_rollovers + rollovers];

		data->credited = std::max(data->credited, now - boost::posix_time::hours(24 * (backed_rollovers - rollovers - 1)))
			           + time_duration(time_duration::hour_type(double(received_today_) / double(average_bytes_sent_per_day) * 24),
			                           time_duration::min_type((double(received_today_) / double(average_bytes_sent_per_day) * (24 * 3600))) % 3600,
			                           0, 0);
	}

	for (int i = days - backed_rollovers; i < days; ++i) {
		data->sent[i] = 0;
		data->received[i] = 0;
	}

	for (int day = 0; day < days; ++day) {
		total_sent_ += data->sent[day];
		total_received_ += data->received[day];
	}

	sent_today_ = data->sent[days-1];
	received_today_ = data->received[days-1];
	credited_ = data->credited;

	if (backed_rollovers)
		rollover_ = data->rollover = now;
}

known_peers::iterator::iterator(const known_peers& peers, const network_key& target)
	: peers_(peers)
{
	sig_buf_.resize(peers_.signer_.signature_length());


	boost::uint64_t bytes_per_day = peers_.average_bytes_sent_per_day();
	boost::posix_time::ptime now = boost::posix_time::second_clock::universal_time();
	boost::posix_time::time_duration max_credit = peers_.max_credited_ - now;

	distance_iterator<known_peers::peers_t> credit(peers_.peers_, target);

	typedef std::map<double, known_peers::peers_t::const_iterator> potentials_t;
	potentials_t potentials;

	for (unsigned closer_credits = 0; closer_credits < peers_.peers_.size(); ++closer_credits, ++credit) {
		double score = (1.0 - (double(closer_credits) / double(peers_.peers_.size())))                                          * 0.5
		               + (double((credit->second.get_credited(now, bytes_per_day) - now).hours()) / double(max_credit.hours())) * 0.5;

		potentials.insert(std::make_pair(score, credit.get()));
	}

	sorted_peers_.reserve(potentials.size());

	for (potentials_t::iterator potential = potentials.begin(); potential != potentials.end(); ++potential)
		sorted_peers_.push_back(potential->second);
}

known_peers::known_peers(boost::asio::io_service& io_service, const std::string& db_path, const author& signer)
	: db_(NULL, 0), total_sent_(0), total_received_(0), next_rollover_(io_service), max_credited_(boost::date_time::min_date_time),
	  signer_(signer)
{
	db_.open(NULL, db_path.c_str(), NULL, DB_BTREE, DB_CREATE, 0);

	Dbc* cursor;
	db_.cursor(NULL, &cursor, 0);

	Dbt key, data;
	network_key id;

	key.set_flags(DB_DBT_USERMEM);
	key.set_data(&id);
	key.set_ulen(sizeof(network_key));

/*	known_peer::packed peer_data;
	data.set_flags(DB_DBT_USERMEM | DB_DBT_PARTIAL);
	data.set_data(&peer_data);
	data.set_size(sizeof(peer_data));
*/

	while (cursor->get(&key, &data, DB_NEXT) == 0) {
		known_peer peer(reinterpret_cast<known_peer::packed*>(data.get_data()));
		peers_.insert(std::make_pair(id, peer));
		total_sent_ += peer.total_sent();
		total_received_ += peer.total_received();
	}

	cursor->close();

	rollover(boost::system::error_code());
}

void known_peers::sent_content(const network_key& id, std::size_t bytes)
{
	transfered_content(id, bytes, offsetof(known_peer::packed, sent[known_peer::days-1]))->second.sent_content(bytes);
	total_sent_ += bytes;
}

void known_peers::received_content(const network_key& id, std::size_t bytes)
{
	known_peers::peers_t::iterator peer = transfered_content(id, bytes, offsetof(known_peer::packed, received[known_peer::days-1]));
	peer->second.received_content(bytes);
	total_received_ += bytes;
	max_credited_ = std::max(max_credited_, peer->second.get_credited(boost::posix_time::second_clock::universal_time(), average_bytes_sent_per_day()));
}
/*
std::vector<known_peers::credit_type> known_peers::best_credits(const network_key& id, unsigned max_returned)
{
#if 0
	struct peer_id_cmp
	{
		bool operator()(const peers_t::value_type& l, const network_key& r)
		{
			return l.first < r;
		}

		bool operator()(const network_key& l, const peers_t::value_type& r)
		{
			return l < r.first;
		}
	};
#endif
	typedef std::vector<boost::tuple<network_key, boost::posix_time::ptime, double> > potentials_t;

#if 0
	if (peers_.empty())
		return std::vector<credit_type>();
#endif

	potentials_t potentials;
	boost::uint64_t bytes_per_day = average_bytes_sent_per_day();
	boost::posix_time::ptime now = boost::posix_time::second_clock::universal_time();
	boost::posix_time::time_duration max_credit = max_credited_ - now;

#if 0
	peers_t::iterator next_peer_high = std::lower_bound(peers_.begin(), peers_.end(), id, peer_id_cmp());
	peers_t::iterator next_peer_low = next_peer_high;

	if (next_peer_low != peers_.begin())
		--next_peer_low;

	int closer_peers = 0;
#endif

	for (peers_t::const_iterator peer = peers_.begin(); peer != peers_.end(); ++peer) {
		double score = ((peer->first - id) / key_max)                                                                       * 0.5
		             + (double((peer->second.get_credited(now, bytes_per_day) - now).hours()) / double(max_credit.hours())) * 0.5;

		for (potentials_t::iterator potential = potentials.begin(); potential != potentials.end(); ++potential) {
			if (score > potential->get<2>()) {
				if (potentials.size() > max_returned)
					potentials.pop_back();
				potentials.insert(potential, boost::make_tuple(peer->first, peer->second.get_credited(now, bytes_per_day), score));
			}
		}
	}

	std::vector<credit_type> ret;

	for (potentials_t::iterator potential = potentials.begin(); potential != potentials.end(); ++potential)
		ret.push_back(credit_type(potential->get<0>(), potential->get<1>()));

	return ret;
}*/
/*
std::pair<known_peers::derived_t::iterator, known_peers::persistent_t::iterator> known_peers::get_record(const network_key& id)
{
	std::pair<derived_t::iterator, bool> total = derived_.insert(std::make_pair(id, derived_data()));
	persistent_t::iterator history;

	if (total.second) {
		total.first->second.rollover = boost::posix_time::second_clock::universal_time().time_of_day();
		total.first->second.total_sent = 0;
		total.first->second.total_received = 0;

		history = persistent_.insert(std::make_pair(id, persistent_data(total.first->second.rollover))).first;
	}
	else {
		history = persistent_.find(id);
	}

	return std::make_pair(total.first, history);
}
*/
known_peers::peers_t::iterator known_peers::transfered_content(network_key id, std::size_t bytes, unsigned data_offset)
{
	Dbt key(&id, sizeof(network_key));
	boost::uint64_t daily_total;
	Dbt data(&daily_total, sizeof(boost::uint64_t));
	data.set_ulen(sizeof(boost::uint64_t));
	data.set_dlen(sizeof(boost::uint64_t));
	data.set_doff(data_offset);
	data.set_flags(DB_DBT_USERMEM | DB_DBT_PARTIAL);

	int result = db_.get(NULL, &key, &data, 0);

	peers_t::iterator peer_entry;

	if (result == DB_NOTFOUND) {
		peer_entry = new_peer(id);
		daily_total = 0;
	}
	else {
		peer_entry = peers_.find(id);
	}

	daily_total += bytes;
	db_.put(NULL, &key, &data, 0);

	return peer_entry;
}

known_peers::peers_t::iterator known_peers::new_peer(network_key id)
{
	known_peer::packed peer_data;

	peer_data.key_length = 0;

	for (int d = 0; d < known_peer::days; ++d) {
		peer_data.sent[d] = 0;
		peer_data.received[d] = 0;
	}

	peer_data.rollover = boost::posix_time::second_clock::universal_time();

	Dbt key(&id, sizeof(network_key));
	Dbt data(&peer_data, sizeof(peer_data));
	db_.put(NULL, &key, &data, 0);

	return peers_.insert(std::make_pair(id, known_peer(reinterpret_cast<known_peer::packed*>(data.get_data())))).first;
}

void known_peers::rollover(const boost::system::error_code& error)
{
	if (!error) {
		boost::posix_time::ptime now = boost::posix_time::second_clock::universal_time();
		boost::posix_time::ptime next_rollover(boost::date_time::max_date_time);
		boost::uint64_t bytes_per_day = average_bytes_sent_per_day();

		for (peers_t::iterator peer = peers_.begin(); peer != peers_.end(); ++peer) {
			if (peer->second.rollover_time() < now) {
				total_sent_ -= peer->second.total_sent();
				total_received_ -= peer->second.total_received();

				Dbt key, data;

				key.set_flags(DB_DBT_USERMEM);
				key.set_data(const_cast<network_key*>(&peer->first));
				key.set_ulen(sizeof(network_key));

				known_peer::packed peer_data;

				data.set_flags(DB_DBT_USERMEM | DB_DBT_PARTIAL);
				data.set_data(&peer_data);
				data.set_ulen(sizeof(known_peer::packed));
				data.set_dlen(sizeof(known_peer::packed));

				db_.get(NULL, &key, &data, 0);

				peer->second.do_rollover(&peer_data, now, bytes_per_day);

				next_rollover = std::min(next_rollover, peer_data.rollover + boost::posix_time::hours(24));

				db_.put(NULL, &key, &data, 0);

				total_sent_ += peer->second.total_sent();
				total_received_ += peer->second.total_received();

				max_credited_ = std::max(max_credited_, peer->second.get_credited(now, bytes_per_day));
			}
		}

		next_rollover_.expires_at(next_rollover);
		next_rollover_.async_wait(boost::bind(&known_peers::rollover, this, placeholders::error));
	}
}
