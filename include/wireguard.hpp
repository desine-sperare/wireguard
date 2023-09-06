#pragma once

#include <stdint.h>
#include <string>
#include <vector>
#include <ctime>
#include <limits>
#include "ipv4.hpp"
#include "json.hpp"
#include "time.hpp"

#define NULL_STRING ""


namespace timlibs
{
	class WireguardException
	{
	public:
		WireguardException();
		WireguardException(const std::string& discription);
		WireguardException(const char* discription);
	private:
		std::string what() const;;
		std::string error_discription;
	};

	struct Client
	{
		std::string uuid{ NULL_STRING }; // UUID of client
		std::string private_key{ NULL_STRING }; // client private key
		std::string public_key{ NULL_STRING }; // client public key
		std::string login{ NULL_STRING }; // client login (short name), ex.: bivanov
		std::string full_name{ NULL_STRING }; // client full name, ex.: Ivanov Boris [Ivanovich]
		IPv4 ip{ NULL_IP_DEC }; // client vpn ip address
		bool account_status{ false }; // client account current status (active, inactive)
		bool administrative_account_status{ false }; // client account administartive status (on, off)
		bool connection_status{ false }; // client connection status (connected, disconnected)
		Time creation_date{ MIN_TIME }; // date when client account was created
		Time release_date{ MIN_TIME }; // date when client account will be activated
		Time expiration_date{ MAX_TIME }; // date when client accaunt will be deactivated
		std::string allowed_ips{ NULL_STRING }; // ip addresses where the client wants to connect via vpn, ex.: "10.0.0.0/16, 10.100.34.0/28, 192.168.31.5/32"
		std::string dns{ NULL_STRING }; // ip address of DNS server (overwrites the DNS server of client)

	};

	struct Server
	{
		std::string interface_name{ NULL_STRING }; // name of wg interface, ex. wg0
		uint16_t listen_port{ NULL }; // port number 1 - 65535
		IPv4 ip{ NULL_IP_DEC }; // server vpn ip address
		IPv4Mask network{ NULL_IP_DEC }; // vpn network
		std::string endpoint_dns{ NULL_STRING }; // public domain name of server (if exist)
		IPv4 endpoint_ip{ NULL_IP_DEC }; // public ip address of server
		uint16_t public_listen_port{ NULL }; // public port number 1 - 65535 (if the server is behind a firewall, the value may differ from listen_port, else - equal)
		std::string private_key{ NULL_STRING }; // server private key
		std::string public_key{ NULL_STRING }; // server public key
		std::string pre_up{ NULL_STRING }; // pre up commands
		std::string post_up{ NULL_STRING }; // post up commands
		std::string pre_down{ NULL_STRING }; // pre down commands
		std::string post_down{ NULL_STRING }; // post down commands
	};

	class Wireguard
	{
	public:
		Wireguard(const std::string& interface_name = NULL_STRING);

		Server GetServer();
		void SetServer(); // тут обновление конфигурации сервера

		std::string CreateClient(Client client);
		Client GetClient(const std::string& uuid);
		std::vector<Client> GetClients();
		void UpgradeClient(const std::string& uuid); // подумай как реализовать обновление полей клиента
		void RemoveClient(const std::string& uuid);


		void Controller(); // Check and modify client account and connection statuses

		// bool SetClientStatus(const std::string& uid, const bool& status); // может не стоит выносить как отдельный метод
	private:
		bool DateAndModeController();
		bool ConnectionStatusController();
		void PeersConnectionController() const;

		void AddPeer(const Client& client) const;
		void RemovePeer(const Client& client) const;
		void RemovePeer(const std::string& public_key) const;
		
		void ReadConfiguration(); //configuration -> json -> json file
		void WriteConfiguration(); //json file -> json -> configuration

		nlohmann::json SerializeConfiguration() const; // configuration -> json
		void DeserializeConfiguration(const nlohmann::json& json_configuration); // json -> configuration

		void WriteServerConfiguration() const; //configuration -> wg0.conf (only server)

		void UploadConfiguration(const nlohmann::json& json_configuration) const; //json -> json file
		nlohmann::json DownloadConfiguration() const; //json file -> json

		void StartServer();
		void StopServer();
		void RebootServer();

		Server server; // server data
		std::vector<Client> clients; // clients data
	};	
}
