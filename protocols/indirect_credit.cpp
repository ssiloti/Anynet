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

#include "indirect_credit.hpp"
#include <payload_failure.hpp>
#include <payload_request.hpp>
#include <node.hpp>
#include <boost/bind/protect.hpp>
#include <boost/bind.hpp>
#include <boost/make_shared.hpp>
#include <stdexcept>

namespace
{
	struct stored_single_credit
	{
	//	network_key recipient;
		boost::posix_time::ptime expires;
		boost::uint16_t signature_length;
	//	boost::uint16_t issuer_length;
	//	boost::uint8_t signature[1];
	};

	template <typename Store>
	class payload_credits : public sendable_payload
	{
	public:
		typedef Store store_type;

		virtual std::vector<const_buffer> serialize(boost::shared_ptr<const packet> pkt, std::size_t threshold, mutable_buffer scratch) const
		{
			boost::uint8_t* scratch_base = buffer_cast<boost::uint8_t*>(scratch);

			const authority& issuer = store_.get_creditor(pkt->source());
			unsigned issuer_size = issuer.serialize();

			if (issuer_size > buffer_size(scratch) + 3)
				throw std::length_error("scratch buffer is too small for credit issuer, this shouldn't happen");

			u16(buffer_cast<boost::uint8_t*>(scratch), boost::uint16_t(issuer_size));
			scratch = scratch + 2;

			issuer.serialize(scratch);
			scratch = scratch + issuer_size;

			boost::uint8_t* credit_count = buffer_cast<boost::uint8_t*>(scratch);
			scratch = scratch + 1;

			typename store_type::iterator credit_iter = store_.begin(pkt->source(), pkt->destination());

			while (credit_iter != store_.end()) {
			//	const typename store_type::credit_type& credit = *credit_iter;
				//const_buffer signature(credit.signature.get());
				if (buffer_size(scratch) < sizeof(packed_single_credit))
					break;

				packed_single_credit* packed_credit = buffer_cast<packed_single_credit*>(scratch);
				credit_iter.recipient().encode(packed_credit->recipient);
				u64(packed_credit->expires, (credit_iter.expires() - epoch).total_seconds());

				const_buffer sig(credit_iter.signature(const_buffer(packed_credit, sizeof(packed_credit->recipient) + sizeof(packed_credit->expires))));

				if (buffer_size(scratch) < buffer_size(sig))
					break;

				u16(packed_credit->signature_size, buffer_size(sig));
				std::memcpy(packed_credit->signature, buffer_cast<const void*>(sig), buffer_size(sig));

				scratch = scratch + sizeof(packed_single_credit) + buffer_size(sig);
				++*credit_count;
				++credit_iter;
			}

			return std::vector<const_buffer>(1, const_buffer(scratch_base, buffer_cast<boost::uint8_t*>(scratch) - scratch_base));
		}

		static std::size_t parse(packet::ptr_t pkt, const_buffer buf, store_type& store)
		{
			std::size_t input_size = buffer_size(buf);

			if (input_size < 2)
				return 0;

			std::size_t issuer_size = u16(buffer_cast<const boost::uint8_t*>(buf));

			if (input_size < 2 + issuer_size)
				return 0;

			buf = buf + 2;

			authority issuer(const_buffer(buffer_cast<const void*>(buf), issuer_size));

			if (!issuer.valid())
				return 0;

			pkt->source(store.store_creditor(const_buffer(buffer_cast<const void*>(buf), issuer_size)));
			buf = buf + issuer_size;

			if (buffer_size(buf) < 1)
				return 0;

			int credit_count = *buffer_cast<const boost::uint8_t*>(buf);
			buf = buf + 1;

			pkt->payload(boost::make_shared<payload_credits<store_type> >(store));
			//payload_credits<store_type>& credits = *pkt->payload_as<payload_credits<store_type> >();

			for (;credit_count > 0; --credit_count) {
				if (buffer_size(buf) < sizeof(packed_single_credit))
					return 0;

				const packed_single_credit* packed_credit = buffer_cast<const packed_single_credit*>(buf);

				boost::uint64_t expires_seconds = u64(packed_credit->expires);
				long expires_hours = long(expires_seconds / 3600);
				expires_seconds %= 3600;
				long expires_minutes = long(expires_seconds / 60);
				expires_seconds %= 60;

				typename store_type::credit_type
					store_credit(network_key(packed_credit->recipient),
					             epoch + boost::posix_time::time_duration(expires_hours, expires_minutes, long(expires_seconds)),
					             const_buffer(buffer_cast<const void*>(buf), sizeof(packed_credit) - sizeof(packed_credit->signature_size)));

				if (!store.store_credit(issuer,
				                        pkt->source(),
				                        store_credit,
				                        const_buffer(buffer_cast<const void*>(buf + sizeof(packed_credit)), u16(packed_credit->signature_size))))
					return 0;

				buf = buf + sizeof(packed_credit) + u16(packed_credit->signature_size);
			}

			return input_size - buffer_size(buf);
		}

		payload_credits(const store_type& store) : store_(store) {}

	private:
		struct packed_single_credit
		{
			boost::uint8_t recipient[network_key::packed_size];
			boost::uint8_t expires[8];
			boost::uint8_t signature_size[2];
			boost::uint8_t signature[];
		};

	/*	struct packet_credit_vector
		{
			boost::uint8_t credit_count;
			boost::uint8_t issuer_size[2];
		};*/

		const store_type& store_;
	};
}

const static boost::posix_time::ptime epoch(boost::gregorian::date(1970, boost::gregorian::Jan, 1));

credit_store::iterator::iterator(const credit_store& store)
	: store_(store)
{}

credit_store::iterator::iterator(const credit_store& store, const network_key& issuer, const network_key& target)
	: store_(store), issuer_(issuer)
{
	credit_store::credits_index_t::const_iterator issuer_credits = store_.credit_index_.find(issuer);

	if (issuer_credits == store_.credit_index_.end())
		return;

	boost::posix_time::ptime max_expires(boost::date_time::min_date_time);

	for (credit_store::credit_index_t::const_iterator credit = issuer_credits->second.begin();
	     credit != issuer_credits->second.end();
	     ++credit) {
		if (credit->second.expires > max_expires)
			max_expires = credit->second.expires;
	}

	boost::posix_time::ptime now = boost::posix_time::second_clock::universal_time();
	boost::posix_time::time_duration max_credited = max_expires - now;

	distance_iterator<credit_store::credit_index_t> credit(issuer_credits->second, target);

	typedef std::map<double, credit_index_t::const_iterator> potentials_t;
	potentials_t potentials;

	for (unsigned closer_credits = 0; closer_credits < issuer_credits->second.size(); ++closer_credits, ++credit) {
		double score = (1.0 - (double(closer_credits) / double(issuer_credits->second.size())))          * 0.5
		               + (double((credit->second.expires - now).hours()) / double(max_credited.hours())) * 0.5;

		potentials.insert(std::make_pair(score, credit.get()));
	}

	sorted_credits_.reserve(potentials.size());

	for (potentials_t::iterator potential = potentials.begin(); potential != potentials.end(); ++potential)
		sorted_credits_.push_back(potential->second);
}

credit_store::credit_store(boost::asio::io_service& io_service, const std::string& db_path)
	: io_service_(io_service), db_(NULL, 0)
{
	db_.open(NULL, db_path.c_str(), NULL, DB_BTREE, DB_CREATE, 0);

	Dbc* cursor;
	db_.cursor(NULL, &cursor, 0);

	Dbt key, data;
	stored_credit_key id;
	boost::posix_time::ptime expires;

	key.set_flags(DB_DBT_USERMEM);
	key.set_data(&id);
	key.set_ulen(sizeof(id));

	key.set_flags(DB_DBT_USERMEM | DB_DBT_PARTIAL);
	key.set_data(&expires);
	key.set_ulen(sizeof(expires));
	key.set_ulen(sizeof(expires));
	key.set_doff(0);

	while (cursor->get(&key, &data, DB_NEXT) == 0) {
		credits_index_t::iterator inserted = credit_index_.insert(std::make_pair(id.issuer, credit_index_t())).first;
		if (id.issuer != id.recipient)
			inserted->second.insert(std::make_pair(id.recipient, issued_credit(expires)));
	}

	cursor->close();
}

authority credit_store::get_creditor(const network_key& id) const
{
	stored_credit_key db_id;
	db_id.issuer = id;
	db_id.recipient = id;
	Dbt key(&db_id, sizeof(db_id));
	key.set_flags(DB_DBT_USERMEM);

	Dbt data;

	int result = db_.get(NULL, &key, &data, 0);

	if (result == DB_NOTFOUND)
		throw std::invalid_argument("Creditor not found");

	return authority(const_buffer(data.get_data(), data.get_size()));
}

credit_store::credit_type credit_store::get_credit(const network_key& creditor, const network_key& recipient) const
{
	stored_credit_key db_id;
	db_id.issuer = creditor;
	db_id.recipient = recipient;
	Dbt key(&db_id, sizeof(db_id));
	key.set_flags(DB_DBT_USERMEM);

	Dbt data;

	int result = db_.get(NULL, &key, &data, 0);

	if (result == DB_NOTFOUND)
		throw std::invalid_argument("Credit not found");

	const stored_credit_data* credit_data = reinterpret_cast<const stored_credit_data*>(data.get_data());
	return credit_type(recipient,
	                   credit_data->expires,
	                   const_buffer(credit_data->signature, credit_data->signature_size));
}

network_key credit_store::store_creditor(const_buffer creditor)
{
	network_key id(creditor);

	stored_credit_key db_id;
	db_id.issuer = id;
	db_id.recipient = id;
	Dbt key(&db_id, sizeof(db_id));
	key.set_flags(DB_DBT_USERMEM);

	Dbt data(const_cast<void*>(buffer_cast<const void*>(creditor)), buffer_size(creditor));
	data.set_flags(DB_DBT_USERMEM);

	db_.put(NULL, &key, &data, 0);

	return id;
}

bool credit_store::store_credit(const authority& creditor,
                                const network_key& creditor_id,
                                const credit_type& credit,
                                const_buffer packed_credit)
{
	if (!creditor.verify(packed_credit, credit.signature))
		return false;

	stored_credit_key db_id;
	db_id.issuer = creditor_id;
	db_id.recipient = credit.recipient;
	Dbt key(&db_id, sizeof(db_id));
	key.set_flags(DB_DBT_USERMEM);

	stored_credit_data db_data;
	db_data.expires = credit.expires;
	db_data.signature_size = buffer_size(credit.signature);

	Dbt data(&db_data, sizeof(db_data));
	data.set_flags(DB_DBT_USERMEM);

	db_.put(NULL, &key, &data, 0);

	data.set_flags(DB_DBT_USERMEM | DB_DBT_PARTIAL);
	data.set_data(const_cast<void*>(buffer_cast<const void*>(credit.signature)));
	data.set_size(buffer_size(credit.signature));
	data.set_dlen(buffer_size(credit.signature));
	data.set_doff(offsetof(stored_credit_data, signature));

	db_.put(NULL, &key, &data, 0);

	return true;
}

indirect_credit::indirect_credit(boost::shared_ptr<local_node> node)
	: network_protocol(node, protocol_id), store_(node->io_service(), node->config().content_store_path() + "/indirect_credits")
{}

void indirect_credit::receive_attached_content(connection::ptr_t con, packet::ptr_t pkt, std::size_t payload_size)
{
	if (payload_size == 0) {
		packet::ptr_t p;
		node_->packet_received(con, p);
		return;
	}

	con->receive_payload(payload_size, boost::protect(boost::bind(&indirect_credit::credits_received, this, con, pkt, _1)));
}

void indirect_credit::to_content_location_failure(packet::ptr_t pkt)
{
	if (store_.have_credits_from(pkt->destination()))
		pkt->to_reply(packet::content_attached, boost::make_shared<payload_credits<credit_store> >(store_));
	else
		pkt->to_reply(packet::content_failure, boost::make_shared<payload_failure>(0));
}

void indirect_credit::request_from_location_failure(packet::ptr_t pkt)
{
	pkt->to_reply(packet::content_requested, boost::make_shared<payload_request>(0));
}

void indirect_credit::snoop_packet_payload(packet::ptr_t pkt)
{
	switch (pkt->content_status())
	{
		case packet::content_requested:
			if (pkt->destination() == node_->id())
				pkt->to_reply(packet::content_attached, boost::make_shared<payload_credits<known_peers> >(node_->get_known_peers()));
			break;
	}
}

void indirect_credit::credits_received(connection::ptr_t con, packet::ptr_t pkt, const_buffer buf)
{
	payload_credits<credit_store>::parse(pkt, buf, store_);
	node_->packet_received(con, pkt);
}
