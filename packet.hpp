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
#include <boost/variant.hpp>
#include <boost/optional.hpp>
#include <map>
#include <algorithm>
#include <cstring>

class connection;

struct content_sources
{
	typedef boost::shared_ptr<content_sources> ptr_t;

	struct source
	{
		source() : stored(boost::posix_time::second_clock::universal_time()) {}
		boost::posix_time::ptime stored;
		boost::optional<network_key> id;
	};

	struct ep_cmp
	{
		bool operator()(const ip::tcp::endpoint& l, const ip::tcp::endpoint& r) const { if (l.address() == r.address()) return l.port() < r.port(); return l.address() < r.address(); }
	};

	typedef std::map<ip::tcp::endpoint, source, ep_cmp> sources_t;

	content_sources(std::size_t s) : size(s), last_stat_source_count(0) {}

	sources_t sources;
	boost::uint32_t size;
	int last_stat_source_count; // the most recent source count which was registered with the sources_per_hunk stats
};

class packet : public boost::enable_shared_from_this<packet>
{
public:
	typedef boost::shared_ptr<packet> ptr_t;
	typedef boost::shared_ptr<const packet> const_ptr_t;

	enum content_status_t
	{
		content_requested = 0,
		content_attached,
		content_detached,
		content_failure
	};

	enum error_code_t
	{
		success = 0,
		not_found,
		unknown_protocol,
	};

	packet(int version = 0) : version_(version), direct_(false) {}

	void to_reply(const_payload_buffer_ptr payload)
	{
		network_key temp = source();
		source(destination());
		destination(temp);
		content_status(content_attached);
		payload_ = payload;
	}

	void to_reply(content_sources::ptr_t sources)
	{
		network_key temp = source();
		source(destination());
		destination(temp);
		content_status(content_detached);
		payload_ = sources;
	}

	void to_reply(error_code_t err)
	{
		network_key temp = source();
		source(destination());
		destination(temp);
		content_status(content_failure);
		payload_ = err;
	}

	void detach_content(content_sources::ptr_t sources)
	{
		content_status(content_detached);
		payload_ = sources;
	}

	/*boost::uint32_t content_size()
	{
		switch (content_status())
		{
		case content_atached:return buffer_size(payload()->get());
		case content_detached:return u32(buffer_cast<boost::uint8_t*>(payload()->get()) + network_key::packed_size);
		default:
			throw std::logic_error("Tried to get content size of packet without content");
		}
	}*/

	std::vector<const_buffer> serialize(mutable_buffer scratch);

	template <typename Handler>
	void receive(net_link& link, Handler handler)
	{
		if (link.valid_recv_bytes >= header_size())
			header_received(link, handler, boost::system::error_code(), 0);
		else
			boost::asio::async_read(link.socket,
			                        mutable_buffers_1(buffer(link.receive_buffer) + link.valid_recv_bytes),
									boost::asio::transfer_at_least(header_size() - link.valid_recv_bytes),
			                        boost::bind(&packet::header_received<Handler>,
			                                    shared_from_this(),
												boost::ref(link),
												handler,
			                                    placeholders::error,
			                                    placeholders::bytes_transferred));
	}

	template <typename Handler>
	void receive_payload(net_link& link, payload_buffer_ptr payload, Handler handler)
	{
		payload_ = payload;
		mutable_buffer buf = payload->get();

		std::memcpy(buffer_cast<void*>(buf), link.receive_buffer.data(), std::min(link.valid_recv_bytes, buffer_size(buf)));

		if (buffer_size(buf) > link.valid_recv_bytes) {
			boost::asio::async_read(link.socket,
			                        mutable_buffers_1(buf + link.valid_recv_bytes),
									boost::bind(&packet::payload_received<Handler>,
			                                    shared_from_this(),
												boost::ref(link),
			                                    handler,
			                                    placeholders::error,
			                                    placeholders::bytes_transferred));
			link.valid_recv_bytes = 0;
//			DLOG(INFO) << "0=" << link.valid_recv_bytes;
		}
		else {
			link.valid_recv_bytes -= buffer_size(buf);
//			DLOG(INFO) << '-' << buffer_size(buf) << ',' << link.valid_recv_bytes;
			std::memmove(link.receive_buffer.data(), link.receive_buffer.data() + buffer_size(buf), link.valid_recv_bytes);
			payload_received(link, handler, boost::system::error_code(), buffer_size(buf));
		}
	}

	template <typename Handler>
	void receive_payload(net_link& link, content_sources::ptr_t sources, Handler handler)
	{
		std::size_t sources_size = parse_detached_sources(link, sources);

		link.valid_recv_bytes -= sources_size;
		if (link.valid_recv_bytes != 0) {
			std::memmove(link.receive_buffer.data(), link.receive_buffer.data() + sources_size, link.valid_recv_bytes);
		}

		ptr_t p(shared_from_this());
		handler(p);
	}

	int version() const { return version_; }
	void version(int v) { version_ = v; }

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

	const_payload_buffer_ptr payload() const { return boost::get<const_payload_buffer_ptr>(payload_); }
	void payload(const_payload_buffer_ptr pl) { payload_ = pl; }

	void payload(error_code_t e) { payload_ = e; }

	boost::uint32_t content_size() { return boost::get<boost::uint32_t>(payload_); }
	void content_size(boost::uint32_t s) { payload_ = s; }

	content_sources::ptr_t sources() const { return boost::get<content_sources::ptr_t>(payload_); }

//	mutable_buffer payload() { return payload_.get(); }

//	virtual ~packet() {}

protected:
	static std::size_t header_size();

private:
	std::size_t serialize_header(boost::uint8_t* buf);
	std::size_t serialize_sources(boost::uint8_t* buf);
	std::size_t parse_header(const boost::uint8_t* header);
	std::size_t parse_detached_sources(net_link& link, content_sources::ptr_t sources);
	void parse_failure(net_link& link);
	void parse_request(net_link& link);
	std::size_t detached_content_size(net_link& link);

	template <typename Handler>
	void header_received(net_link& link,
	                     Handler handler,
	                     const boost::system::error_code& error,
	                     std::size_t bytes_transferred)
	{
		if (error || !link.socket.is_open()) {
			DLOG(INFO) << "Error receiving packet header" << error;
			ptr_t p;
			handler(p, bytes_transferred);
			return;
		}

		std::size_t payload_size = parse_header(link.receive_buffer.data());
		link.valid_recv_bytes += bytes_transferred - header_size();
//		DLOG(INFO) << '+' << bytes_transferred - header_size() << ',' << link.valid_recv_bytes;

//		DLOG(INFO) << "Received packet header dest=" << std::string(destination());

		if (link.valid_recv_bytes)
			std::memmove(link.receive_buffer.data(), link.receive_buffer.data() + header_size(), link.valid_recv_bytes);

		if (content_status() != content_attached) {
			// non-content payloads are required to fit into our receive buffer, so go ahead and buffer the whole thing up
			// before notifying the handler
			if (link.valid_recv_bytes < payload_size)
				boost::asio::async_read(link.socket,
				                        mutable_buffers_1(buffer(link.receive_buffer) + link.valid_recv_bytes),
				                        boost::asio::transfer_at_least(payload_size - link.valid_recv_bytes),
				                        boost::bind(&packet::aux_header_received<Handler>,
				                                    shared_from_this(),
				                                    boost::ref(link),
													payload_size,
				                                    handler,
				                                    placeholders::error,
				                                    placeholders::bytes_transferred));
			else
				aux_header_received(link, payload_size, handler, error, 0);
		}
		else {
			ptr_t p(shared_from_this());
			handler(p, payload_size);
		}
	}

	template <typename Handler>
	void aux_header_received(net_link& link,
	                         std::size_t payload_size,
	                         Handler handler,
	                         const boost::system::error_code& error,
	                         std::size_t bytes_transferred)
	{
		if (error || !link.socket.is_open()) {
			DLOG(INFO) << "Error receiving packet header" << error;
			ptr_t p;
			handler(p, payload_size);
			return;
		}
		
		link.valid_recv_bytes += bytes_transferred;

		// The first field of the aux header is always the network key of the content in question
		source(network_key(link.receive_buffer.data()));

		if (content_status() == content_requested) {
			parse_request(link);
			// for requests the source is all there is, so go ahead and consume it right here
			link.valid_recv_bytes -= payload_size;
			if (link.valid_recv_bytes)
				std::memmove(link.receive_buffer.data(), link.receive_buffer.data() + payload_size, link.valid_recv_bytes);
			payload_size = 0;
		}
		else if (content_status() == content_detached) {
			// for detached content we need to parse out the actual content size from the header
			payload_size = detached_content_size(link);
		}
		else if (content_status() == content_failure) {
			parse_failure(link);
			link.valid_recv_bytes -= payload_size;
			if (link.valid_recv_bytes)
				std::memmove(link.receive_buffer.data(), link.receive_buffer.data() + payload_size, link.valid_recv_bytes);
			payload_size = 0;
		}

		ptr_t p(shared_from_this());
		handler(p, payload_size);
	}

	template <typename Handler>
	void payload_received(net_link& link, Handler handler, const boost::system::error_code& error, std::size_t bytes_transferred)
	{
		ptr_t p;
		if (!error && link.socket.is_open()) {
			p = shared_from_this();
		}
		else {
			DLOG(INFO) << "Error receiving packet payload" << error;
		}
		handler(p);
	}

	boost::uint8_t version_;
	bool direct_;
	protocol_t protocol_;
//	bool is_v6;
	content_status_t content_status_;
	network_key source_;
	network_key destination_;
protected:
	boost::variant<const_payload_buffer_ptr, content_sources::ptr_t, error_code_t, boost::uint32_t> payload_;
};

#endif
