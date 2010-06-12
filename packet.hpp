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

#ifndef PACKET_HPP
#define PACKET_HPP

#include <glog/logging.h>

#include "link.hpp"
#include "key.hpp"
#include "core.hpp"
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/bind.hpp>
#include <boost/optional.hpp>
#include <map>
#include <algorithm>
#include <cstring>

class connection;
class packet;

class sendable_payload
{
public:
	virtual std::size_t content_size() const
	{
		return 0;
	}

	virtual std::vector<const_buffer> serialize(boost::shared_ptr<packet> pkt, std::size_t threshold, mutable_buffer scratch) const = 0;
	virtual ~sendable_payload() {}
};

class packet : public boost::enable_shared_from_this<packet>, public content_frame
{
public:
	typedef boost::shared_ptr<packet> ptr_t;
	typedef boost::shared_ptr<const packet> const_ptr_t;
	typedef std::auto_ptr<const sendable_payload> payload_ptr_t;

	enum content_status_t
	{
		content_requested = 0,
		content_attached,
		content_detached,
		content_failure
	};

	packet() : direct_(false) {}

	void to_reply(content_status_t status, sendable_payload* payload = NULL)
	{
		network_key temp = source();
		source(destination());
		destination(temp);
		content_status(status);
		payload_ = payload_ptr_t(payload);
	}

	virtual std::vector<const_buffer> serialize(std::size_t threshold, mutable_buffer scratch);

	template <typename Handler>
	void receive(net_link& link, Handler handler)
	{
		if (link.valid_received_bytes() >= header_size())
			header_received(link, handler, boost::system::error_code(), 0);
		else
			boost::asio::async_read(link.socket,
			                        mutable_buffers_1(link.receive_buffer(header_size())),
			                        boost::asio::transfer_at_least(header_size() - link.valid_received_bytes()),
			                        boost::bind(&packet::header_received<Handler>,
			                                    shared_from_this(),
			                                    boost::ref(link),
			                                    handler,
			                                    placeholders::error,
			                                    placeholders::bytes_transferred));
	}

	protocol_t protocol() const { return protocol_; }
	void protocol(protocol_t p) { protocol_ = p; }

	content_status_t content_status() const { return content_status_; }
	void content_status(content_status_t s) { content_status_ = s; }

	const network_key& source() const { return source_; }
	void source(const network_key& s) { source_ = s; }

	const network_key& destination() const { return destination_; };
	void destination(const network_key& d) { destination_ = d; }

	void mark_direct() { direct_ = true; }
	bool is_direct() const { return direct_; }

	const sendable_payload* payload() const { return payload_.get(); }
	template <typename Payload>
	const Payload* payload_as() const { return dynamic_cast<const Payload*>(payload_.get()); }
	void payload(sendable_payload* p) { payload_ = std::auto_ptr<sendable_payload>(p); }

protected:
	static std::size_t header_size();

private:
	std::size_t serialize_header(mutable_buffer buf);
	std::size_t parse_header(const_buffer buf);

	template <typename Handler>
	void header_received(net_link& link,
	                     Handler handler,
	                     const boost::system::error_code& error,
	                     std::size_t bytes_transferred)
	{
		if (error || !link.socket.lowest_layer().is_open()) {
			DLOG(INFO) << "Error receiving packet header" << error;
			ptr_t p;
			handler(p, bytes_transferred);
			return;
		}

		link.received(bytes_transferred);

		std::size_t payload_size = parse_header(link.received_buffer());
//		DLOG(INFO) << '+' << bytes_transferred - header_size() << ',' << link.valid_recv_bytes;

//		DLOG(INFO) << "Received packet header dest=" << std::string(destination());

		link.consume_receive_buffer(header_size());
		ptr_t p(shared_from_this());
		handler(p, payload_size);
	}

	bool direct_;
	protocol_t protocol_;
	content_status_t content_status_;
	network_key source_;
	network_key destination_;
protected:
	payload_ptr_t payload_;
};

#endif
