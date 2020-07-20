# STM32-MySQL mbed
MySQL Client for STM32 using [Mbed library](https://github.com/ARMmbed/mbed-os)

# How to use this code ?
## Hardware
![alt text](https://os.mbed.com/media/cache/platforms/DISCO_F746NG.jpg.250x250_q85.jpg)

It can be executed on every target with Ethernet/WiFi.
This code has been tested on the [32F746GDISCOVERY](https://www.st.com/en/evaluation-tools/32f746gdiscovery.html)
## IDE
### IDE Used
To compile and flash this code I used [Mbed Studio](https://os.mbed.com/studio/)
### Implement this code
- Add the library to your mbed project (Right click on you project folder, and select **Add Library...**)
- Setup your network connection
- Create a TCP socket and initialize it
- Create a MySQL object by passing the initialized socket into the constructor argument

# main.c Exeample
## Code
```C++
#include "mbed.h"
#include "EthernetInterface.h"
#include "STM32_MySQL.h"

int main(void){
    EthernetInterface eth;
    TCPSocket sock;

    SocketAddress ip;
    SocketAddress server;

    const char* device_ip = "Your STM32 IP";
    const char* server_ip = "Your SQL server IP";
    const char* gateway = "Your gateway";
    const char* netmask = "Your getmask";
    const int mysql_port = 3306;
    char* mysql_user = (char*)"Your user";
    char* mysql_password = (char*)"Your password";

    eth.set_dhcp(false);
    eth.set_network(device_ip, netmask, gateway);
    eth.connect();
    sock.open(&eth);
    server.set_ip_address(server_ip);
    server.set_port(mysql_port);
    sock.set_timeout(1000);
    sock.connect(server);
    
    MySQL sql(&sock);

    sql.connect(mysql_user, mysql_password);

    TypeDef_Database* Database = NULL;

    while(true){
        Database = sql.query("SELECT * FROM database.table;",Database);
        if(Database==NULL) printf("Error : Database NULL after query\r\n");
        else sql.printDatabase(Database);

        ThisThread::sleep_for(5s);
    }
    return 0;
}
```
## Edit
### Configure the constants
```C++
const char* device_ip = "Your STM32 IP";
const char* server_ip = "Your SQL server IP";
const char* gateway = "Your gateway";
const char* netmask = "Your getmask";
char* mysql_user = (char*)"Your user";
char* mysql_password = (char*)"Your password";
```
### Run query with your own database name and table
```C++
Database = sql.query("SELECT * FROM database.table;",Database);
```
