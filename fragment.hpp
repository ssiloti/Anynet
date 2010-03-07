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

#ifndef FRAGMENT_HPP
#define FRAGMENT_HPP

#include "link.hpp"
#include "key.hpp"
#include "hunk.hpp"
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/ip/address.hpp>
#include <list>

/*
struct const_content_fragment
{
	const_content_fragment(content_store::const_mapped_content_ptr c, std::size_t o, std::size_t s) : content_(c), offset(o), buf(c->get() + o, s) {}
	const std::size_t offset;
	const const_buffer buf;
private:
	const content_store::const_mapped_content_ptr content_;
};
*/

class frame_fragment;

class framented_content
{
public:
	struct fragment_buffer
	{
		friend class framented_content;
		const std::size_t offset;
		const mutable_buffer buf;
		const payload_buffer_ptr content;
		fragment_buffer(std::size_t o = 0, std::size_t s = 0, payload_buffer_ptr c = payload_buffer_ptr()) : content(c), offset(o), buf(buffer(c->get() + o, s)) {}
	};

	framented_content(payload_buffer_ptr c) : content_(c) { invalid_.push_back(fragment(0, buffer_size(c->get()), ip::address(), fragment::invalid)); }

	std::pair<std::size_t, std::size_t> next_invalid_range() { if (invalid_.empty()) return std::make_pair(0, 0); return std::make_pair(invalid_.front().offset, invalid_.front().size); }
	fragment_buffer get_fragment_buffer(std::size_t offset, std::size_t size);
	void mark_valid(boost::shared_ptr<frame_fragment> frag, ip::address source);
	const_payload_buffer_ptr complete();
	void reset();

private:
	struct fragment
	{
		enum fragment_state
		{
			invalid,
			requested,
			receiving,
			valid,
		};
		fragment(std::size_t o, std::size_t s, ip::address src, fragment_state st) : offset(o), size(s), source(src), state(st) {}
		std::size_t offset,size;
		fragment_state state;
		ip::address source;
	};
	std::list<fragment> valid_;
	std::list<fragment> requested_;
	std::list<fragment> receiving_;
	std::list<fragment> invalid_;
	payload_buffer_ptr content_;
};

class frame_fragment : public boost::enable_shared_from_this<frame_fragment>, public content_frame
{
public:
	typedef boost::shared_ptr<frame_fragment> ptr_t;

	enum fragment_status
	{
		status_requested = 0,
		status_attached,
		// status 2 reserved
		status_failed = 3,
	};

	frame_fragment(protocol_t proto, network_key i, std::size_t o, std::size_t s, const_payload_buffer_ptr payload = const_payload_buffer_ptr())
		: protocol_(proto), id_(i), offset_(o), size_(s), payload_(payload), status_(payload ? status_attached : status_requested) {}
	frame_fragment(protocol_t proto, network_key i) : protocol_(proto), id_(i), status_(status_failed) {}
	frame_fragment() : status_(status_failed) {}

	protocol_t protocol() const { return protocol_; }
	const network_key& id() const { return id_; }
	std::size_t offset() const { return offset_; }
	std::size_t size() const { return size_; }
	void trim_to(std::size_t s) { size_ = std::min(size_, s); }
	void payload(const_payload_buffer_ptr p) { payload_ = p; }

	fragment_status status() { return status_; }

	const_buffer buf() const { return buffer(payload_->get() + offset_, size_); }

	bool is_request() { return status_ == status_requested; }
	void to_request(std::size_t o, std::size_t s);

	void to_reply(const_payload_buffer_ptr p);
	void to_reply() { status_ = status_failed; }

	virtual std::vector<const_buffer> serialize(std::size_t threshold, mutable_buffer scratch);

	template <typename Handler>
	void receive(net_link& link, Handler handler)
	{
		if (link.valid_received_bytes() >= header_size())
			header_received(link, handler, boost::system::error_code(), 0);
		else
			boost::asio::async_read(link.socket,
			                        mutable_buffers_1(link.receive_buffer()),
									boost::asio::transfer_at_least(header_size() - link.valid_received_bytes()),
			                        boost::bind(&frame_fragment::header_received<Handler>,
			                                    shared_from_this(),
												boost::ref(link),
												handler,
			                                    placeholders::error,
			                                    placeholders::bytes_transferred));
	}

	// For future UDP support
	std::size_t parse(const_buffer& buf)
	{
		if (buffer_size(buf) < header_size())
			return 0;

		std::size_t payload_size = parse_header(buf);

		buf = buf + header_size();

		return payload_size;
	}

	void attach_padding(boost::shared_ptr<heap_buffer> buf) { padding_.push_back(buf); }
	void clear_padding() { padding_.clear(); }

private:
	std::size_t serialize_header(boost::uint8_t* buf);
	std::size_t parse_header(const_buffer buf);
	std::size_t header_size();

	template <typename Handler>
	void header_received(net_link& link,
	                     Handler handler,
	                     const boost::system::error_code& error,
	                     std::size_t bytes_transferred)
	{
		if (error || !link.socket.lowest_layer().is_open()) {
			DLOG(INFO) << "Error receiving fragment frame" << error;
			ptr_t p;
			handler(p, bytes_transferred);
			return;
		}

		std::size_t payload_size = parse_header(link.received_buffer());
		link.received(header_size());
		link.consume_receive_buffer(header_size());

		ptr_t p(shared_from_this());
		handler(p, payload_size);
	}

	template <typename Handler>
	void payload_received(net_link& link, Handler handler, const boost::system::error_code& error, std::size_t bytes_transferred)
	{
		padding_.clear();

		ptr_t p;
		if (!error && link.socket.is_open()) {
			p = shared_from_this();
		}
		else {
			DLOG(INFO) << "Error receiving fragment payload" << error;
		}
		handler(p);
	}

	std::size_t offset_, size_;
	network_key id_;
	const_payload_buffer_ptr payload_;
	std::vector<boost::shared_ptr<heap_buffer> > padding_;
	protocol_t protocol_;
	fragment_status status_;
};

#endif