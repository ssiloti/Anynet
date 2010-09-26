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

#ifndef PROTOCOLS_INDIRECT_CREDIT_HPP
#define PROTOCOLS_INDIRECT_CREDIT_HPP

#include "known_peers.hpp"
#include "authority.hpp"
#include <protocol.hpp>
#include <db_cxx.h>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <map>
#include <vector>
#include <list>

class credit_store
{
	friend class iterator;
public:
	struct issued_credit
	{
		issued_credit(boost::posix_time::ptime e) : expires(e), active_request_count_(0) {}

		boost::posix_time::ptime expires;
		int active_request_count_;
	};

	typedef std::map<network_key, issued_credit> credit_index_t;

	struct credit_type
	{
		credit_type() {}
		credit_type(network_key r, boost::posix_time::ptime e, const_buffer s)
			: recipient(r), expires(e), signature(s) {}

		network_key recipient;
		boost::posix_time::ptime expires;
		const_buffer signature;
	};

	class iterator
	{
		friend class credit_store;
	public:
		iterator& operator++()
		{
			sorted_credits_.pop_back();
			credit_ = store_.get_credit(issuer_, sorted_credits_.back()->first);
			return *this;
		}

		const network_key& recipient()
		{
			return credit_.recipient;
		}

		const boost::posix_time::ptime& expires()
		{
			return credit_.expires;
		}

		const_buffer signature(const_buffer packed_credit)
		{
			return credit_.signature;
		}

		bool operator==(const iterator& other)
		{
			// for now we just check for equality with the end interator
			return sorted_credits_.empty() && other.sorted_credits_.empty();
		}

		bool operator!=(const iterator& other)
		{
			// for now we just check for equality with the end interator
			return !sorted_credits_.empty() || !other.sorted_credits_.empty();
		}

	private:
		typedef std::vector<credit_index_t::const_iterator> sorted_credits_t;

		iterator(const credit_store& store);
		iterator(const credit_store& store, const network_key& issuer, const network_key& target);

		const credit_store& store_;
		network_key issuer_;
		sorted_credits_t sorted_credits_;
		credit_type credit_;
	};

	credit_store(boost::asio::io_service& io_service, const std::string& db_path);

	iterator begin(const network_key& issuer, const network_key& target) const
	{
		return iterator(*this, issuer, target);
	}

	iterator end() const { return iterator(*this); }

	bool have_credits_from(const network_key& id) { return credit_index_.count(id) != 0; }

	authority get_creditor(const network_key& id) const;
	credit_type get_credit(const network_key& creditor, const network_key& recipient) const;

	network_key store_creditor(const_buffer creditor);

	// Returns true if credit was stored successfully, false if the signature was invalid
	bool store_credit(const authority& creditor,
	                  const network_key& creditor_id,
	                  const credit_type& credit,
	                  const_buffer packed_credit);

	const credit_index_t& get_credits(const network_key& creditor);

private:
	typedef std::map<network_key, credit_index_t> credits_index_t;

	struct stored_credit_key
	{
		network_key issuer, recipient;
	};

	struct stored_credit_data
	{
		boost::posix_time::ptime expires;
		boost::uint16_t signature_size;
		boost::uint8_t signature[];
	};

	boost::asio::io_service& io_service_;
	mutable Db db_; // the BerkeleyDB API is not const correct
	credits_index_t credit_index_;
};

class indirect_credit : public network_protocol
{
public:
	static const protocol_id protocol_id = protocol_sha1_rsa_credits;

	static void create(local_node& node)
	{
		boost::shared_ptr<indirect_credit> ptr(new indirect_credit(node));
		ptr->register_handler();
		//ptr->start_vacume();
	}

	virtual void receive_attached_content(connection::ptr_t con, packet::ptr_t pkt, std::size_t payload_size);

	virtual void to_content_location_failure(packet::ptr_t pkt);
	virtual void request_from_location_failure(packet::ptr_t pkt);

	virtual void prune_hunk(const network_key& id) {}

protected:
	virtual void snoop_packet_payload(packet::ptr_t pkt);

private:
	indirect_credit(local_node& node);

	void credits_received(connection::ptr_t con, packet::ptr_t pkt, const_buffer buf);

	credit_store store_;
};

#endif
