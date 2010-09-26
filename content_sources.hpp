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

#ifndef CONTENT_SOURCES_HPP
#define CONTENT_SOURCES_HPP

#include "packet.hpp"
#include "key.hpp"
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <boost/enable_shared_from_this.hpp>

struct content_sources : public boost::enable_shared_from_this<content_sources>
{
	typedef boost::shared_ptr<content_sources> ptr_t;

	struct source
	{
		source()
			: stored(boost::posix_time::second_clock::universal_time())
			, active_request_count(0)
		{}

		source(ip::tcp::endpoint ep)
			: stored(boost::posix_time::second_clock::universal_time())
			, ep(ep)
		{}

		boost::posix_time::ptime stored;
		ip::tcp::endpoint ep;
		unsigned int active_request_count;
	};

	struct ep_cmp
	{
		bool operator()(const ip::tcp::endpoint& l, const ip::tcp::endpoint& r) const
		{
			if (l.address() == r.address())
				return l.port() < r.port();
			else
				return l.address() < r.address();
		}
	};

	typedef std::map<network_key, source> sources_t;

	content_sources(content_size_t s) : size(s), last_stat_source_count(0) {}

	sendable_payload::ptr_t get_payload();

	sources_t sources;
	content_size_t size;
	int last_stat_source_count; // the most recent source count which was registered with the sources_per_hunk stats
};

#endif
