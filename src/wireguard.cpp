#include "wireguard.hpp"
#include "uuid.hpp"
#include <fstream>
#include "wg_utils.hpp"
#include <set>
#include "ipv4.hpp"

#define ROOT_PATH "/etc/wireguard/"
#define DELTA_HANDSHAKE_TIME 130

#define INTERFACE_NAME_DEFAULT "wg0"
#define LISTEN_PORT_DEFAULT 55255
#define ENDPOINT_IP_DEFAULT "127.0.0.1"
#define ENDPOINT_DNS_DEFAULT ""
#define IP_DEFAULT "10.0.30.1"
#define NETMASK_DEFAULT "255.255.255.0"
#define PRIVATE_KEY_DEFAULT
#define PUBLIC_KEY_DEFAULT
#define PRE_UP_DEFAULT "echo Wireguard PreUp"
#define POST_UP_DEFAULT "echo Wireguard PostUp"
#define PRE_DOWN_DEFAULT "echo Wireguard PreDown"
#define POST_DOWN_DEFAULT "echo Wireguard PostDown"

namespace timlibs
{

    WireguardException::WireguardException() : error_discription{ NULL_STRING } {}


    WireguardException::WireguardException(const std::string& discription) : error_discription{ discription } {}


    WireguardException::WireguardException(const char* discription) : error_discription{ discription } {}


    std::string WireguardException::what() const { return this->error_discription; }
}

namespace timlibs
{
    namespace general
    {
        enum KEY
        {
            FIRST,
            SERVER = FIRST,
            CLIENTS,
            LAST // leave it as the last value!!!
        };
    }
    
    namespace server
    {
        enum KEY
        {
            FIRST = general::KEY::LAST,
            INTERFACE_NAME = FIRST,
            LISTEN_PORT,
            IP,
            NETWORK,
            ENDPOINT_DNS,
            ENDPOINT_IP,
            PUBLIC_LISTEN_PORT,
            PRIVATE_KEY,
            PUBLIC_KEY,
            PRE_UP,
            POST_UP,
            PRE_DOWN,
            POST_DOWN,
            LAST // leave it as the last value!!!
        };
    }
    
    namespace clients
    {
        enum KEY
        {
            FIRST = server::KEY::LAST,
            UUID = FIRST,
            PRIVATE_KEY,
            PUBLIC_KEY,
            LOGIN,
            FULL_NAME,
            IP,
            ACCOUNT_STATUS,
            ADMINISTRATIVE_ACCOUNT_STATUS,
            CONNECTION_STATUS,
            CREATION_DATE,
            RELEASE_DATE,
            EXPIRATION_DATE,
            ALLOWED_IPS,
            DNS,
            LAST
        };
    }
    
    const std::unordered_map<uint32_t, std::string> keys
    {
        {general::KEY::SERVER, "server"},
        {server::KEY::INTERFACE_NAME, "interface_name"},
        {server::KEY::LISTEN_PORT, "listen_port"},
        {server::KEY::IP, "ip"},
        {server::KEY::NETWORK, "network"},
        {server::KEY::ENDPOINT_DNS, "endpoint_dns"},
        {server::KEY::ENDPOINT_IP, "endpoint_ip"},
        {server::KEY::PUBLIC_LISTEN_PORT, "public_listen_port"},
        {server::KEY::PRIVATE_KEY, "private_key"},
        {server::KEY::PUBLIC_KEY, "public_key"},
        {server::KEY::PRE_UP, "pre_up"},
        {server::KEY::POST_UP, "post_up"},
        {server::KEY::PRE_DOWN, "pre_down"},
        {server::KEY::POST_DOWN, "post_down"},
        {general::KEY::CLIENTS, "clients"},
        {clients::KEY::UUID, "uuid"},
        {clients::KEY::PRIVATE_KEY, "private_key"},
        {clients::KEY::PUBLIC_KEY, "public_key"},
        {clients::KEY::LOGIN, "login"},
        {clients::KEY::FULL_NAME, "full_name"},
        {clients::KEY::IP, "ip"},
        {clients::KEY::ACCOUNT_STATUS, "account_status"},
        {clients::KEY::ADMINISTRATIVE_ACCOUNT_STATUS, "administrative_account_status"},
        {clients::KEY::CONNECTION_STATUS, "connection_status"},
        {clients::KEY::CREATION_DATE, "creation_date"},
        {clients::KEY::RELEASE_DATE, "release_date"},
        {clients::KEY::EXPIRATION_DATE, "expiration_date"},
        {clients::KEY::ALLOWED_IPS, "allowed_ips"},
        {clients::KEY::DNS, "dns"}
    };


    /// @brief Initialize the wireguard server
    /// @param interface_name name of wireguard interface, ex. wg0
    Wireguard::Wireguard(const std::string& interface_name)
    {
        //if file exist - load, else new configuration
        if (interface_name == NULL_STRING) this->server.interface_name = INTERFACE_NAME_DEFAULT;
        else this->server.interface_name = interface_name;
        if (std::ifstream(ROOT_PATH + this->server.interface_name + ".json")) this->ReadConfiguration();
        else
        {
            // Бляяя, я заебался уже писать
        }
    }

    /// @brief Gets server configuration
    /// @return server configuration as Server structure
    Server Wireguard::GetServer() { return this -> server; }

    /// @brief Creates a client
    /// @param client object of Client class that containt information about client
    /// @return UUID of new client
    std::string Wireguard::CreateClient(Client client)
    {
        // написать ебейшие проверки, да и вообще подумать
        client.uuid = generate_uuid();
        this->clients.push_back(client);
        return client.uuid;
    }

    /// @brief Returns copy of client by it's UUID
    /// @param uuid UUID of client
    /// @return client configuration as Client structure
    Client Wireguard::GetClient(const std::string& uuid)
    {
        for (Client client : this->clients)
        {
            if (client.uuid == uuid) return client;
        }
        throw WireguardException("Client id is not found");
    }

    /// @brief Controls that real configuration is equal to configuration in RAM.
    /// @brief It's using DateAndModeController, ConnectionStatusController, PeersConnectionController
    void Wireguard::Controller()
    {
        this->PeersConnectionController();
        if (this->DateAndModeController() && this->ConnectionStatusController()) this->SerializeConfiguration();
    }

    /// @brief Controls dates of client and accaunt status of clients
    /// @return Flag of changes in configuration
    bool Wireguard::DateAndModeController()
    {
        time_t now = time(nullptr);
        bool any_changes_flag = true;
        for (Client client : this->clients)
        {
            if (client.administrative_account_status)
            {
                if (client.account_status)
                {
                    if (client.expiration_date < now)
                    {
                        client.account_status = false;
                        any_changes_flag = true;
                    }
                }
                else
                {
                    if (client.release_date > now and client.expiration_date < now)
                    {
                        client.account_status = true;
                        any_changes_flag = true;
                    }
                }
            }
            else
            {
                if (client.account_status) // if client account status is "active", we must shut it down
                {
                    client.account_status = false;
                    any_changes_flag = true;
                }
            }
        }
        return any_changes_flag;
    }

    /// @brief Controls connection statuses of clients
    /// @return Flag of changes in configuration
    bool Wireguard::ConnectionStatusController()
    {
        auto hadshackes = wg_show_latest_handshakes(this->server.interface_name);
        Time now(time(nullptr));
        bool any_changes = false;

        for (auto handshacke : hadshackes)
        {
            for (Client& client : this->clients)
            {
                if (client.public_key == handshacke.first)
                {
                    if (now - handshacke.second < DELTA_HANDSHAKE_TIME && client.connection_status != true)
                    {
                        client.connection_status = true;
                        any_changes = true;
                    }
                    if (now - handshacke.second > DELTA_HANDSHAKE_TIME && client.connection_status != false)
                    {
                        client.connection_status = false;
                        any_changes = true;
                    }
                }
                break;
            }
        }
        return any_changes;
    }

    /// @brief Controls that only allowed peers may be in current wireguard configuration
    void Wireguard::PeersConnectionController() const
    {
        std::vector<std::string> peers_public_keys_vector = wg_show_peers(this->server.interface_name);

        std::set<std::string> current_peers(std::make_move_iterator(peers_public_keys_vector.begin()), std::make_move_iterator(peers_public_keys_vector.end()));
        std::set<std::string> active_clients{};

        for (const Client& client : this->clients)
        {
            if (client.account_status) active_clients.insert(client.public_key);
        }

        std::set<std::string> illegal_peers{};
        std::set_intersection(current_peers.begin(), current_peers.end(), active_clients.begin(), active_clients.end(), std::inserter(illegal_peers, illegal_peers.begin()));

        std::set<std::string> legal_peers_not_added{};
        std::set_intersection(active_clients.begin(), active_clients.end(), current_peers.begin(), current_peers.end(), std::inserter(legal_peers_not_added, legal_peers_not_added.begin()));

        for (const std::string& public_key : illegal_peers) this->RemovePeer(public_key);
        for (const std::string& public_key : legal_peers_not_added)
        {
            for (const Client& client : this->clients)
            {
                if (client.public_key == public_key)
                {
                    this->AddPeer(client);
                    break;
                }
            }
        }
        // и сравнивать с теми, кто должен там быть
    }

    /// @brief Add a peer to wireguard configuration by client link
    /// @param client link to client object
    void Wireguard::AddPeer(const Client& client) const
    {
        wg_set(this->server.interface_name, client.public_key, client.allowed_ips);
    }

    /// @brief Remove a peer from wireguard configuration by client link
    /// @param client link to client object
    void Wireguard::RemovePeer(const Client& client) const
    {
        this->RemovePeer(client.public_key);
    }

    /// @brief Remove a peer from wireguard configuration by public key
    /// @param public_key public key of peer
    void Wireguard::RemovePeer(const std::string& public_key) const
    {
        wg_set_remove(this->server.interface_name, public_key);
    }

    /// @brief Converts configuration from jsom file to configuration in RAM
    void Wireguard::ReadConfiguration()
    {
        DeserializeConfiguration(this->DownloadConfiguration());
    }

    /// @brief Converts configuration  in RAM to json file
    void Wireguard::WriteConfiguration()
    {
        UploadConfiguration(this->SerializeConfiguration());
    }

    /// @brief Converts configuration in RAM to JSON object
    /// @return Configuration as JSON object
    nlohmann::json Wireguard::SerializeConfiguration() const
    {
        nlohmann::json json_configuration;
        nlohmann::json json_server_configuration;
        nlohmann::json json_users_configuration;


        json_server_configuration[keys.at(server::KEY::INTERFACE_NAME)] = this->server.interface_name;
        json_server_configuration[keys.at(server::KEY::LISTEN_PORT)] = this->server.listen_port;
        json_server_configuration[keys.at(server::KEY::IP)] = this->server.ip.GetAsString();
        json_server_configuration[keys.at(server::KEY::NETWORK)] = this->server.network.GetAsString();
        json_server_configuration[keys.at(server::KEY::ENDPOINT_DNS)] = this->server.endpoint_dns;
        json_server_configuration[keys.at(server::KEY::ENDPOINT_IP)] = this->server.endpoint_ip.GetAsString();
        json_server_configuration[keys.at(server::KEY::PUBLIC_LISTEN_PORT)] = this->server.public_listen_port;
        json_server_configuration[keys.at(server::KEY::PRIVATE_KEY)] = this->server.private_key;
        json_server_configuration[keys.at(server::KEY::PUBLIC_KEY)] = this->server.public_key;
        json_server_configuration[keys.at(server::KEY::PRE_UP)] = this->server.pre_up;
        json_server_configuration[keys.at(server::KEY::POST_UP)] = this->server.post_up;
        json_server_configuration[keys.at(server::KEY::PRE_DOWN)] = this->server.pre_down;
        json_server_configuration[keys.at(server::KEY::POST_DOWN)] = this->server.post_down;

        json_users_configuration = nlohmann::json::array();
        for (Client client : this->clients)
        {
            nlohmann::json json_user_configuration;
            json_user_configuration[keys.at(clients::KEY::UUID)] = client.uuid;
            json_user_configuration[keys.at(clients::KEY::PRIVATE_KEY)] = client.private_key;
            json_user_configuration[keys.at(clients::KEY::PUBLIC_KEY)] = client.public_key;
            json_user_configuration[keys.at(clients::KEY::LOGIN)] = client.login;
            json_user_configuration[keys.at(clients::KEY::FULL_NAME)] = client.full_name;
            json_user_configuration[keys.at(clients::KEY::IP)] = client.ip.GetAsString();
            json_user_configuration[keys.at(clients::KEY::ACCOUNT_STATUS)] = client.account_status;
            json_user_configuration[keys.at(clients::KEY::ADMINISTRATIVE_ACCOUNT_STATUS)] = client.administrative_account_status;
            json_user_configuration[keys.at(clients::KEY::CONNECTION_STATUS)] = client.connection_status;
            json_user_configuration[keys.at(clients::KEY::CREATION_DATE)] = client.creation_date.GetAsString();
            json_user_configuration[keys.at(clients::KEY::RELEASE_DATE)] = client.release_date.GetAsString();
            json_user_configuration[keys.at(clients::KEY::EXPIRATION_DATE)] = client.expiration_date.GetAsString();
            json_user_configuration[keys.at(clients::KEY::ALLOWED_IPS)] = client.allowed_ips;

            json_users_configuration.push_back(json_user_configuration);
        }

        json_configuration[keys.at(general::KEY::SERVER)] = json_server_configuration;
        json_configuration[keys.at(general::KEY::CLIENTS)] = json_users_configuration;

        return json_configuration;
    }

    /// @brief Converts JSON object to configuration in RAM
    /// @param json_configuration JSON object
    void Wireguard::DeserializeConfiguration(const nlohmann::json& json_configuration)
    {
        nlohmann::json json_server_configuration = json_configuration[keys.at(general::KEY::SERVER)];
        nlohmann::json json_users_configuration = json_configuration[keys.at(general::KEY::CLIENTS)];

        // Deserialize server config
        this->server.interface_name = json_server_configuration[keys.at(server::KEY::INTERFACE_NAME)];
        this->server.listen_port = json_server_configuration[keys.at(server::KEY::LISTEN_PORT)];
        if (!json_server_configuration[keys.at(server::KEY::ENDPOINT_DNS)].is_null()) this->server.endpoint_dns = json_server_configuration[keys.at(server::KEY::ENDPOINT_DNS)];
        if (!json_server_configuration[keys.at(server::KEY::ENDPOINT_IP)].is_null()) this->server.endpoint_dns = json_server_configuration[keys.at(server::KEY::ENDPOINT_IP)];
        this->server.public_listen_port = json_server_configuration[keys.at(server::KEY::PUBLIC_LISTEN_PORT)];
        this->server.private_key = json_server_configuration[keys.at(server::KEY::PRIVATE_KEY)];
        this->server.public_key = json_server_configuration[keys.at(server::KEY::PUBLIC_KEY)];
        this->server.pre_up = (!json_server_configuration[keys.at(server::KEY::PRE_UP)].is_null()) ? json_server_configuration[keys.at(server::KEY::PRE_UP)] : PRE_UP_DEFAULT;
        this->server.post_up = (!json_server_configuration[keys.at(server::KEY::POST_UP)].is_null()) ? json_server_configuration[keys.at(server::KEY::POST_UP)] : PRE_UP_DEFAULT;
        this->server.pre_down = (!json_server_configuration[keys.at(server::KEY::PRE_DOWN)].is_null()) ? json_server_configuration[keys.at(server::KEY::PRE_DOWN)] : PRE_UP_DEFAULT;
        this->server.post_down = (!json_server_configuration[keys.at(server::KEY::POST_DOWN)].is_null()) ? json_server_configuration[keys.at(server::KEY::POST_DOWN)] : PRE_UP_DEFAULT;
        try
        {
            this->server.ip = IPv4((std::string)json_server_configuration[keys.at(server::KEY::IP)]);
            this->server.network = IPv4Mask((std::string)json_server_configuration[keys.at(server::KEY::NETWORK)]);
        }
        catch (const ExceptionIPv4& error)
        {
            throw WireguardException("Server IPv4 Error: " + error.what());
        }
        catch (...)
        {
            throw;
        }

        // Deserialize clients config
        for (const nlohmann::json& json_user_configuration : json_users_configuration)
        {
            Client client;
            if (is_correct(json_user_configuration[keys.at(clients::KEY::UUID)])) client.uuid = json_user_configuration[keys.at(clients::KEY::UUID)];
            else throw WireguardException("UUID for client isn't correct");
            client.private_key = json_user_configuration[keys.at(clients::KEY::PRIVATE_KEY)];
            client.public_key = json_user_configuration[keys.at(clients::KEY::PUBLIC_KEY)];
            client.login = json_user_configuration[keys.at(clients::KEY::LOGIN)];
            client.full_name = json_user_configuration[keys.at(clients::KEY::FULL_NAME)];
            client.connection_status = false;
            client.account_status = false;
            client.administrative_account_status = json_user_configuration[keys.at(clients::KEY::ADMINISTRATIVE_ACCOUNT_STATUS)];
            client.release_date = (!json_user_configuration[keys.at(clients::KEY::RELEASE_DATE)].is_null()) ? Time((std::string)json_user_configuration[keys.at(clients::KEY::RELEASE_DATE)]) : MIN_TIME;
            client.expiration_date = (!json_user_configuration[keys.at(clients::KEY::EXPIRATION_DATE)].is_null()) ? Time((std::string)json_user_configuration[keys.at(clients::KEY::EXPIRATION_DATE)]) : MAX_TIME;
            if (Time::IsValid(json_user_configuration[keys.at(clients::KEY::CREATION_DATE)])) client.creation_date = Time((std::string)json_user_configuration[keys.at(clients::KEY::CREATION_DATE)]);
            else throw WireguardException("Client creation date isn't valid");
            client.allowed_ips = json_user_configuration[keys.at(clients::KEY::ALLOWED_IPS)];

            try
            {
                client.ip = IPv4((std::string)json_user_configuration[keys.at(clients::KEY::IP)]);
            }
            catch (const ExceptionIPv4& error)
            {
                throw WireguardException("Client IPv4 Error: " + error.what());
            }
            catch (...)
            {
                throw;
            }

            this->clients.push_back(client);
        }
    }

    /// @brief Converts server configuration in RAM to wg.conf file of server configuration
    void Wireguard::WriteServerConfiguration() const
    {
        //тут написать как переводить конфиг в файл конфига wg (wg0.conf)
        //прям записать в файл
    }

    /// @brief Writes JSON object to json file
    /// @param json_configuration JSON object
    void Wireguard::UploadConfiguration(const nlohmann::json& json_configuration) const
    {
        std::ofstream file(ROOT_PATH + this->server.interface_name + ".json");
        if (file.is_open()) file << std::setw(4) << json_configuration;
        else
        {
            throw WireguardException("Unable access to " + this->server.interface_name + ".json");
            exit(EXIT_FAILURE);
        }
        file.close();
    }

    /// @brief Read JSON file and convert in to JSON object
    /// @return JSON object
    nlohmann::json Wireguard::DownloadConfiguration() const
    {
#pragma region Парсинг_ср-ми_библиотеки
        nlohmann::json json_configuration;
        std::ifstream file(ROOT_PATH + this->server.interface_name + ".json");
        if (file.is_open())
        {
            try
            {
                json_configuration = nlohmann::json::parse(file);
            }
            catch (const nlohmann::json::parse_error& error)
            {
                throw WireguardException("json::parse_error");
            }
            catch (...)
            {
                throw;
            }

        }
        else throw WireguardException("Unable access to " + this->server.interface_name + ".json");
        file.close();
#pragma endregion

#pragma region Проверка_наличия_полей

#pragma region Проверка_наличия_полей_server_и_clients
        // Check that general section for keys
        for (uint32_t key = general::KEY::FIRST; key < general::KEY::LAST; key++)
        {
            if (!json_configuration.contains(keys.at(key))) throw WireguardException("No section in configuration file: \"" + keys.at(key) + '"');
        }
#pragma endregion
        nlohmann::json json_server_configuration = json_configuration[keys.at(general::KEY::SERVER)];
        nlohmann::json json_clients_configuration = json_configuration[keys.at(general::KEY::CLIENTS)];
#pragma region Проверка_наличия_полей_в_секции_server
        // Check server section for keys
        for (uint32_t key = server::KEY::FIRST; key < server::KEY::LAST; key++)
        {
            if (!json_server_configuration.contains(keys.at(key))) throw WireguardException("No section \"" + keys.at(key) + "\" of section \"" + keys.at(general::KEY::SERVER) + "\" in configuration file");
        }
#pragma endregion

#pragma region Проверка_наличия_полей_секции_clients
        // Check clients section for keys
        for (const nlohmann::json& json_client_configuration : json_clients_configuration)
        {
            for (uint32_t key = clients::KEY::FIRST; key < clients::KEY::LAST; key++)
            {
                if (!json_clients_configuration.contains(keys.at(key))) throw WireguardException("No section \"" + keys.at(key) + "\" of section \"" + keys.at(general::KEY::CLIENTS) + "\" in configuration file");
            }
        }    
#pragma endregion

#pragma endregion

#pragma region Проверка_типов_полей

#pragma region Проверка_типов_полей_server_и_clients
        // Check types of fields in general section
        if (!json_server_configuration.is_object()) throw WireguardException("Section \"" + keys.at(general::KEY::SERVER) + "\" must be object type");
        if (!json_clients_configuration.is_array()) throw WireguardException("Section \"" + keys.at(general::KEY::CLIENTS) + "\" must be array type");
#pragma endregion

#pragma region Проверка_типов_полей_секции_server
        // Check types of fields in server section
        for (uint32_t key = server::KEY::FIRST; key < server::KEY::LAST; key++)
        {
            if (key != server::KEY::LISTEN_PORT && key != server::KEY::PUBLIC_LISTEN_PORT) // all without numeric fields
            {
                if (key != server::KEY::ENDPOINT_DNS && key != server::KEY::ENDPOINT_IP) // fields that only may be string type
                {
                    if (!json_server_configuration[keys.at(key)].is_string()) throw WireguardException("Field \"" + keys.at(key) + "\" of section \"" + keys.at(general::KEY::SERVER) + "\" must be string type");
                }
                else // fields that may be string or null type (ENDPOINT_DNS and ENDPOINT_IP)
                {
                    if (!json_server_configuration[keys.at(key)].is_string() && !json_server_configuration[keys.at(key)].is_null()) throw WireguardException("Field \"" + keys.at(key) + "\" of section \"" + keys.at(general::KEY::SERVER) + "\" must be string or null type"); // just check string or null
                }
            }
            else //numeric fields
            {
                if (!json_server_configuration[keys.at(key)].is_number_unsigned()) throw WireguardException("Field \"" + keys.at(key) + "\" of section \"" + keys.at(general::KEY::SERVER) + "\" must be unsigned integer type");
            }
        }
        // Check that at least one of fields (ENDPOINT_DNS and ENDPOINT_IP) is not null type
        if (json_server_configuration[keys.at(server::KEY::ENDPOINT_DNS)].is_null() && json_server_configuration[keys.at(server::KEY::ENDPOINT_IP)].is_null()) throw WireguardException("One of the fields, \"" + keys.at(server::KEY::ENDPOINT_DNS) + "\" or \"" + keys.at(server::KEY::ENDPOINT_IP) + "\", of section \"" + keys.at(general::KEY::SERVER) + "\" must be string type");
#pragma endregion

#pragma region Проверка_типов_полей_секции_clients
        // Check types of fields in clients section
        for (const nlohmann::json& json_client_configuration : json_clients_configuration) // itterate clients
        {
            if (!json_client_configuration.is_object()) throw WireguardException("Element of section \"" + keys.at(general::KEY::CLIENTS) + "\" must be object type"); // client must be object type
            for (uint32_t key = clients::KEY::FIRST; key < clients::KEY::LAST; key++)
            {
                if (key != clients::KEY::ACCOUNT_STATUS && key != clients::KEY::ADMINISTRATIVE_ACCOUNT_STATUS && key != clients::KEY::CONNECTION_STATUS) // all without bool fields
                {
                    if (key != clients::KEY::RELEASE_DATE && key != clients::KEY::EXPIRATION_DATE) // fields that only may be string type
                    {
                        if (!json_client_configuration[keys.at(key)].is_string()) throw WireguardException("Field \"" + keys.at(key) + "\" of section \"" + keys.at(general::KEY::CLIENTS) + "\" must be string type");
                    }
                    else // fields that may be string or null type (RELEASE_DATE and EXPIRATION_DATE)
                    {
                        if (!json_server_configuration[keys.at(key)].is_string() && !json_server_configuration[keys.at(key)].is_null()) throw WireguardException("Field \"" + keys.at(key) + "\" of section \"" + keys.at(general::KEY::CLIENTS) + "\" must be string or null type"); // just check string or null
                    }
                }
                else // bool fields
                {
                    if (key != clients::KEY::CONNECTION_STATUS)
                    {
                        if (!json_client_configuration[keys.at(key)].is_boolean()) throw WireguardException("Field \"" + keys.at(key) + "\" of section \"" + keys.at(general::KEY::CLIENTS) + "\" must be boolean type");
                    }
                    else // field CONNECTION_STATUS may be bool or null type
                    {
                        if (!json_client_configuration[keys.at(key)].is_boolean() && !json_client_configuration[keys.at(key)].is_null()) throw WireguardException("Field \"" + keys.at(key) + "\" of section \"" + keys.at(general::KEY::CLIENTS) + "\" must be boolean or null type");
                    }
                }
            }
        }
#pragma endregion

#pragma endregion

        return json_configuration;
    }

    /// @brief Gets list of clients
    /// @return list of Client structures as clients configuration
    std::vector<Client> Wireguard::GetClients()
    {
        return this->clients;
    }

    /// @brief Remove client from configuration by it's UUID
    /// @param uuid UUID of client
    void Wireguard::RemoveClient(const std::string& uuid)
    {
        for (std::vector<Client>::iterator itter = this->clients.begin(); itter != this->clients.end(); itter++)
        {
            if (itter->uuid == uuid)
            {
                this->clients.erase(itter);
                break;
            }
        }
    }

    /// @brief Starts the wireguard server with clients
    void Wireguard::StartServer()
    {
        wg_quick_up(this->server.interface_name);
        for (Client client : this->clients)
        {
            if (client.account_status) this->AddPeer(client);
        }
    }

    /// @brief Stops the wireguard server
    void Wireguard::StopServer()
    {
        wg_quick_down(this->server.interface_name);
    }

    /// @brief Reboots the wireguard server, by stop start commands
    void Wireguard::RebootServer()
    {
        this->StopServer();
        this->StartServer();
    }
}