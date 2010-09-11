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

#ifndef CORE_HPP
#define CORE_HPP

#pragma warning (disable : 4200)

#include <glog/logging.h>

#include "link.hpp"
#include <boost/cstdint.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/interprocess/mapped_region.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <boost/smart_ptr.hpp>
#include <vector>
#include <set>

typedef boost::uint16_t signature_scheme_id;
typedef boost::uint64_t content_size_t;

enum defined_signature_schemes
{
	signature_sha256            = 0,
	signature_sha1_rsa          = 1,
	signature_sha1_rsa_x509     = 2,
	signature_sha1_rsa_credits  = 3,
	signature_sha1_sha2         = 4,
};

class network_key;

/*
class payload_buffer
{
public:
	virtual mutable_buffer get() = 0;
	virtual const_buffer get() const = 0;
	virtual ~payload_buffer() {}
};


typedef boost::shared_ptr<payload_buffer> payload_buffer_ptr;
typedef boost::shared_ptr<const payload_buffer> const_payload_buffer_ptr;
*/

class content_frame
{
public:
	typedef boost::shared_ptr<content_frame> ptr_t;

	virtual std::vector<const_buffer> serialize(std::size_t threshold, mutable_buffer scratch) = 0;
};

class const_shared_buffer
{
public:
	virtual const_buffer get() const = 0;
	virtual ~const_shared_buffer() {}
};

class mutable_shared_buffer : public const_shared_buffer
{
public:
	virtual mutable_buffer get() = 0;
};

typedef boost::shared_ptr<mutable_shared_buffer> payload_buffer_ptr;
typedef boost::shared_ptr<const_shared_buffer>   const_payload_buffer_ptr;

class heap_buffer : public mutable_shared_buffer
{
public:
	explicit heap_buffer(std::size_t size = 0) : buffer_(size) {}
	void resize(std::size_t new_size) { buffer_.resize(new_size); }

	virtual mutable_buffer get() { return buffer(buffer_); }
	virtual const_buffer get() const { return buffer(buffer_); }
private:
	std::vector<boost::uint8_t> buffer_;
};

class sub_buffer : public const_shared_buffer
{
public:
	sub_buffer(const_payload_buffer_ptr payload, const_buffer sub_buf) : payload_(payload), sub_buffer_(sub_buf) {}

	virtual const_buffer get() const { return sub_buffer_; }

private:
	const_payload_buffer_ptr payload_;
	const_buffer sub_buffer_;
};

extern const network_key key_max;
extern const network_key key_min;

class rolling_stats
{
public:
	rolling_stats() : mean_(0.0), var_(0.0), stddev_(0.0), count_(0) {}

	void add(double new_val)
	{
		++count_;
		double delta = new_val - mean_;
		mean_ += delta / count_;
		var_ = ((count_-1)*var_ + delta * (new_val - mean_)) / count_;
		stddev_ = std::sqrt(var_);
	}

	void remove(double old_val)
	{
        --count_;
		if (count_ == 0) {
            mean_ = 0;
            var_ = 0;
            stddev_ = 0;
		}
		else {
            double delta = old_val - mean_;
            mean_ = mean_ - delta / count_;
            var_ = ((count_+1)*var_ - delta*(old_val - mean_)) / count_;
			stddev_ = std::sqrt(var_);
		}
	}

	void update(double old_val, double new_val)
	{
        double newdelta = new_val - mean_;
        double olddelta = old_val - mean_;
        double oldmean = mean_ - olddelta / count_;
        mean_ = oldmean + newdelta / count_;
        var_ = (count_*var_ - olddelta*(old_val - oldmean) + newdelta * (new_val - mean_)) / count_;
		stddev_ = std::sqrt(var_);
	}

	double mean() { return mean_; }
	double var() { return var_; }
	double stddev() { return stddev_; }

private:
	double mean_, var_, stddev_;
	int count_;
};

template <typename Map>
class distance_iterator
{
	typedef Map map_type;
	typedef typename map_type::const_iterator iterator;
public:
	distance_iterator(const map_type& map, const typename map_type::key_type& target)
		: target_(target), map_(map)
	{
		low_ = map_.lower_bound(target_);

		if (low_ == map_.begin())
			low_ = --map_.end();
		else
			--low_;

		high_ = low_;

		++high_;

		if (high_ == map_.end())
			high_ = map_.begin();

		low_dist_ = target_ - low_->first;
		high_dist_ = high_->first - target_;

		if (low_dist_ < high_dist_)
			cur_ = low_;
		else
			cur_ = high_;
	}

	distance_iterator<map_type>& operator++()
	{
		if (low_ != high_) {
			if (cur_ == low_) {
				if (low_ == map_.begin())
					low_ = --map_.end();
				else
					--low_;
				low_dist_ = target_ - low_->first;
			}
			else {
				++high_;
				if (high_ == map_.end())
					high_ = map_.begin();
				high_dist_ = high_->first - target_;
			}
		}

		if (low_dist_ < high_dist_)
			cur_ = low_;
		else
			cur_ = high_;

		return *this;
	}

	const typename map_type::value_type& operator*()
	{
		return *cur_;
	}

	const typename map_type::value_type* operator->()
	{
		return &(*cur_);
	}

	iterator get() { return cur_; }

private:
	const map_type& map_;
	typename map_type::key_type low_dist_, high_dist_, target_;
	iterator low_, high_, cur_;
};

#endif