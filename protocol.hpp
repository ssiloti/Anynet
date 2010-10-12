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

#ifndef PROTOCOL_HPP
#define PROTOCOL_HPP

#include <glog/logging.h>

#include "content_sources.hpp"
#include "packet.hpp"
#include "connection.hpp"
#include <boost/asio/deadline_timer.hpp>
#include <boost/smart_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/optional.hpp>
#include <boost/cstdint.hpp>

class local_node;

class network_protocol : public boost::enable_shared_from_this<network_protocol>
{
public:
	struct crumb
	{
		struct requester
		{
			//requester(boost::weak_ptr<connection> c, content_size_t t)
			//	: con(c), min_oob_threshold(t)
			//{}

			boost::weak_ptr<connection> con;
			std::size_t min_oob_threshold;
		};

		typedef std::map<network_key, requester> requesters_t;

		crumb(boost::asio::io_service& ios)
			: timeout(ios)
		{
			timeout.expires_from_now(boost::posix_time::seconds(5));
		}

		requesters_t requesters;
		boost::asio::deadline_timer timeout;
	};

	typedef std::map<content_identifier, boost::shared_ptr<crumb> > crumbs_t;

protected:
	const static boost::posix_time::time_duration min_successor_source_age;

public:
	typedef boost::shared_ptr<network_protocol> ptr_t;

	network_protocol(local_node& node, protocol_id p);
	virtual ~network_protocol() {}

	protocol_id id() const { return protocol_; }

	void receive_payload(connection::ptr_t con, packet::ptr_t pkt, std::size_t payload_size);

	// Convert request packet to general failure
	void to_content_location_failure(packet::ptr_t pkt);

	// Convert general failure packet to request, used for desperation mode
	void request_from_location_failure(packet::ptr_t pkt);

	void snoop_packet(packet::ptr_t pkt);

	virtual void prune_hunk(const content_identifier& id) {}

	void register_handler();

	content_sources::ptr_t get_content_sources(content_identifier id, content_size_t size);

	void drop_crumb(packet::ptr_t pkt, boost::weak_ptr<connection> c);
	void pickup_crumb(packet::ptr_t pkt);
	void pickup_crumb(const content_identifier& cid, const boost::system::error_code& error);
	boost::optional<const crumb::requesters_t&> get_crumb(packet::ptr_t pkt);

	virtual void shutdown() { shutting_down_ = true; crumbs_.clear(); }

	template <typename T>
	boost::shared_ptr<T> shared_from_this_as() { return boost::static_pointer_cast<T>(shared_from_this()); }
	template <typename T>
	boost::shared_ptr<T const> shared_from_this_as() const { return boost::static_pointer_cast<T const>(shared_from_this()); }

protected:
	typedef std::map<content_identifier, boost::array<boost::posix_time::ptime, 2> > content_requests_t;
	typedef std::map<content_identifier, content_sources::ptr_t> content_sources_t;

	virtual void receive_attached_content(connection::ptr_t con, packet::ptr_t pkt, std::size_t payload_size);

	void sources_received(connection::ptr_t con, packet::ptr_t pkt, const_buffer buf);
	void request_received(connection::ptr_t con, packet::ptr_t pkt, const_buffer buf);
	void failure_received(connection::ptr_t con, packet::ptr_t pkt, const_buffer buf);

	virtual void snoop_packet_payload(packet::ptr_t pkt) {}

	void start_vacume();

	local_node& node_;
	network_key node_id;
	content_requests_t recent_requests_;
	content_sources_t content_sources_;
	boost::asio::deadline_timer vacume_sources_;
	crumbs_t crumbs_;
	protocol_id protocol_;
	bool shutting_down_;

private:
	void vacume_sources(const boost::system::error_code& error = boost::system::error_code());
};

#endif
