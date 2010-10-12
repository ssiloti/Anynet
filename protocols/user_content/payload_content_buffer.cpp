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

#include "payload_content_buffer.hpp"
#include "content_protocol.hpp"
#include <payload_sources.hpp>
#include <boost/make_shared.hpp>

using namespace user_content;

boost::shared_ptr<const packet> payload_content_buffer::trim(boost::shared_ptr<const packet> pkt, std::size_t threshold) const
{
	const_buffer buf = payload->get();
	if (buffer_size(buf) > threshold) {
		packet::ptr_t detached_pkt(boost::make_shared<packet>(*pkt));
		detached_pkt->content_status(packet::content_detached);
		detached_pkt->payload(origin_.self_source(buffer_size(buf)));
		return detached_pkt;
	}
	else
		return pkt;
}
