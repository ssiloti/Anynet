#include "node.hpp"
#include <iostream>

int main()
{
	boost::asio::io_service io_service;
	local_node node(io_service);
	network_simulator(node, io_service);
	io_service.run();
	return 0;
}