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

#include "fragmented_content.hpp"
#include "content_protocol.hpp"
#include "link.hpp"
#include "content.hpp"
#include "hunk.hpp"
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/ip/address.hpp>

namespace user_content
{

class frame_fragment : public boost::enable_shared_from_this<frame_fragment>, public protocol_frame
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

	frame_fragment(protocol_id proto,
	               content_identifier i,
	               std::size_t o,
	               std::size_t s,
	               const_payload_buffer_ptr payload = const_payload_buffer_ptr())
		: protocol_(proto), id_(i), offset_(o), size_(s), payload_(payload), status_(payload ? status_attached : status_requested)
	{}

	frame_fragment(protocol_id proto, content_identifier i = content_identifier())
		: protocol_(proto), id_(i), status_(status_failed) {}

	//frame_fragment() : status_(status_failed) {}

	protocol_id protocol() const { return protocol_; }
	const content_identifier& id() const { return id_; }
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

	virtual bool done() { return size() == 0 || status() != status_attached; }
	virtual void send_failure(local_node& node, const network_key& dest);

	template <typename Handler>
	void receive_payload(net_link& link, boost::shared_ptr<content_protocol> protocol, Handler handler)
	{
		if (link.valid_received_bytes() >= header_size())
			header_received(link, protocol, handler, boost::system::error_code(), 0);
		else
			boost::asio::async_read(link.socket,
			                        mutable_buffers_1(link.receive_buffer()),
			                        boost::asio::transfer_at_least(header_size() - link.valid_received_bytes()),
			                        boost::bind(&frame_fragment::header_received<Handler>,
			                                    shared_from_this(),
			                                    boost::ref(link),
			                                    protocol,
			                                    handler,
			                                    placeholders::error,
			                                    placeholders::bytes_transferred));
	}

	// For future UDP support
#if 0
	std::size_t parse(const_buffer& buf)
	{
		if (buffer_size(buf) < header_size())
			return 0;

		std::size_t payload_size = parse_header(buf);

		buf = buf + header_size();

		return payload_size;
	}
#endif

	void attach_padding(boost::shared_ptr<heap_buffer> buf) { padding_.push_back(buf); }
	void clear_padding() { padding_.clear(); }

private:
	std::size_t serialize_header(mutable_buffer buf);
	unsigned parse_header(const_buffer buf);
	std::size_t header_size();

	template <typename Handler>
	void header_received(net_link& link,
	                     boost::shared_ptr<content_protocol> protocol,
	                     Handler handler,
	                     const boost::system::error_code& error,
	                     std::size_t bytes_transferred)
	{
		if (error || !link.socket.lowest_layer().is_open()) {
			DLOG(INFO) << "Error receiving fragment frame" << error;
			handler(error, bytes_transferred);
			return;
		}

		unsigned name_components = parse_header(link.received_buffer());
		link.received(bytes_transferred);
		link.consume_receive_buffer(header_size());

		id_.name.receive(name_components,
		                 link,
		                 boost::protect(boost::bind(&frame_fragment::name_received<Handler>,
		                                            shared_from_this(),
		                                            boost::ref(link),
		                                            protocol,
		                                            handler,
		                                            placeholders::error)));
	}

	template <typename Handler>
	void name_received(net_link& link,
	                   boost::shared_ptr<content_protocol> protocol,
	                   Handler handler,
	                   const boost::system::error_code& error)
	{
		if (error || !link.socket.lowest_layer().is_open()
		    || (status() == status_attached && size() == 0)) {
			DLOG(INFO) << "Error receiving fragment frame" << error;
			handler(error, 0);
			return;
		}

		if (status() == status_attached)
		{
			framented_content::fragment_buffer payload = protocol->get_fragment_buffer(shared_from_this());

		#if 0
			if (buffer_size(payload.buf) == 0) {
				node_.receive_failure(con);
				return;
			}
		#endif

			assert(payload.offset >= offset());
			assert(buffer_size(payload.buf) <= size());

			std::vector<mutable_buffer> buffers;

			std::size_t head_excess = payload.offset - offset();

			std::size_t consumable = std::min(head_excess, link.valid_received_bytes());
			link.consume_receive_buffer(consumable);
			head_excess -= consumable;

			if (head_excess) {
				boost::shared_ptr<heap_buffer> head_pad(boost::make_shared<heap_buffer>(head_excess));
				attach_padding(head_pad);
				buffers.push_back(head_pad->get());
			}

			if (buffer_size(payload.buf))
				buffers.push_back(payload.buf);

			this->payload(payload.content);

			std::size_t tail_excess = size() - buffer_size(payload.buf) - (payload.offset - offset());

		//	tail_excess -= con->discard_payload(tail_excess);

			if (tail_excess) {
				boost::shared_ptr<heap_buffer> tail_pad(boost::make_shared<heap_buffer>(tail_excess));
				attach_padding(tail_pad);
				buffers.push_back(tail_pad->get());
			}
		
			link.receive_into(buffers,
			                  boost::bind(&frame_fragment::payload_received<Handler>,
			                              shared_from_this(),
			                              boost::ref(link),
			                              handler,
			                              placeholders::error,
			                              placeholders::bytes_transferred));
		}
		else {
			handler(error, 0);
		}
	}

	template <typename Handler>
	void payload_received(net_link& link, Handler handler, const boost::system::error_code& error, std::size_t bytes_transferred)
	{
		padding_.clear();
#if 0
		ptr_t p;
		if (!error && link.socket.is_open()) {
			p = shared_from_this();
		}
		else {
			DLOG(INFO) << "Error receiving fragment payload" << error;
		}
#endif
		handler(error, bytes_transferred);
	}

	std::size_t offset_, size_;
	content_identifier id_;
	const_payload_buffer_ptr payload_;
	std::vector<boost::shared_ptr<heap_buffer> > padding_;
	protocol_id protocol_;
	fragment_status status_;
};

}

#endif
