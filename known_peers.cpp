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
	boost::posix_time::ptime rollover;
	ip::tcp::endpoint ip;
	boost::uint16_t key_length;
	boost::uint8_t pubkey[1];
};

known_peers::known_peer::known_peer(packed* data)
	: total_sent_(0), total_received_(0), pubkey_(NULL), endpoint_(data->ip), rollover_(data->rollover.time_of_day())
{
	boost::posix_time::time_duration since_rollover = boost::posix_time::second_clock::universal_time() - data->rollover;
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
/*
void known_peers::known_peer::rollover(const network_key& id)
{
	Dbt key;
	boost::uint64_t total_xfered = 0;
	for (int day = 0; day < days-1; ++day) {
		sent_[day+1] = sent_[day];
		reveived_[day+1] = reveived_[day];
	}
	sent_[0] = 0;
	reveived_[0] = 0;
}
*/
known_peers::known_peers(const std::string& db_path)
	: db_(NULL, 0), total_sent_(0), total_received_(0)
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
}

void known_peers::sent_content(const network_key& id, std::size_t bytes)
{
	transfered_content(id, bytes, offsetof(known_peer::packed, sent[known_peer::days-1]))->second.sent_content(bytes);
	total_sent_ += bytes;
}

void known_peers::received_content(const network_key& id, std::size_t bytes)
{
	transfered_content(id, bytes, offsetof(known_peer::packed, received[known_peer::days-1]))->second.received_content(bytes);
	total_received_ += bytes;
}
/*
std::vector<std::pair<network_key, boost::uint64_t> > known_peers::best_credits(const network_key& id, unsigned int max_returned)
{
	typedef std::vector<boost::tuple<network_key, boost::uint64_t, double> > potentials_t;
	potentials_t potentials;

	for (derived_t::const_iterator total = derived_.begin(); total != derived_.end(); ++total) {
		double score = ((total->first - id) / key_max) * 0.5 + (total->second.total_received / total_received_) * 0.5;
		for (potentials_t::iterator potential = potentials.begin(); potential != potentials.end(); ++potential) {
			if (score > potential->get<2>()) {
				if (potentials.size() > max_returned)
					potentials.pop_back();
				potentials.insert(potential, boost::make_tuple(total->first, total->second.total_received, score));
			}
		}
	}

	std::vector<std::pair<network_key, boost::uint64_t> > ret;

	for (potentials_t::iterator potential = potentials.begin(); potential != potentials.end(); ++potential)
		ret.push_back(std::make_pair(potential->get<0>(), potential->get<1>()));

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

	return peers_.insert(std::make_pair(id, known_peer(peer_data.rollover.time_of_day()))).first;
}
