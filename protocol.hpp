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

#include "packet.hpp"
#include "connection.hpp"
#include <boost/asio/deadline_timer.hpp>
#include <boost/smart_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/range/iterator_range.hpp>
#include <boost/cstdint.hpp>

class local_node;

class network_protocol : public boost::enable_shared_from_this<network_protocol>
{
	friend class remote_request_handler;

	struct crumb
	{
		crumb(boost::weak_ptr<connection> c, boost::asio::io_service& ios)
			: timeout(ios), con(c) { timeout.expires_from_now(boost::posix_time::seconds(5)); }
		boost::weak_ptr<connection> con;
		boost::asio::deadline_timer timeout;
	};

protected:
	const static boost::posix_time::time_duration min_successor_source_age;

public:
	typedef boost::shared_ptr<network_protocol> ptr_t;

	struct crumb_cmp
	{
		bool operator()(std::pair<network_key, network_key> x, std::pair<network_key, network_key> y) const
		{
			if (x.first == y.first)
				return x.second < y.second;
			else
				return x.first < y.first;
		}
	};

	typedef std::map<std::pair<network_key, network_key>, boost::shared_ptr<crumb>, crumb_cmp> crumbs_t;

	virtual ~network_protocol() {}
	virtual protocol_t id() = 0;

	virtual void receive_payload(connection::ptr_t con, packet::ptr_t pkt, std::size_t payload_size) = 0;

	// Convert request packet to general failure
	virtual void to_content_location_failure(packet::ptr_t pkt) = 0;
	// Convert general failure packet to request, used for desperation mode
	virtual void request_from_location_failure(packet::ptr_t pkt) = 0;

	void snoop_packet(packet::ptr_t pkt);

	virtual void prune_hunk(const network_key& id) = 0;

	void register_handler();

	void drop_crumb(const std::pair<network_key, network_key>& k, boost::weak_ptr<connection> c);
	boost::shared_ptr<connection> pickup_crumb(const std::pair<network_key, network_key>& k, const boost::system::error_code& error = boost::system::error_code());
	boost::shared_ptr<connection> get_crumb(const std::pair<network_key, network_key>& k);

	virtual void shutdown() { shutting_down_ = true; crumbs_.clear(); }

protected:
	typedef std::map<network_key, boost::array<boost::posix_time::ptime, 2> > content_requests_t;

	network_protocol(local_node& node);

	virtual void snoop_packet_payload(packet::ptr_t pkt) = 0;

	local_node& node_;
	network_key node_id;
	content_requests_t recent_requests_;
	bool shutting_down_;

private:

	crumbs_t crumbs_;
};

#endif