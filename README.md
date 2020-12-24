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
## Code (With DNS)
```C++
#include "mbed.h"
#include "EthernetInterface.h"
#include "STM32_MySQL.h"

//Your favourite network interface
EthernetInterface eth;

//The TCP socket used to communicate with the MySQL server
TCPSocket tcpSocket;

int main(void){
	//Network constants
	const char* server_ip =	"Your MySQL Server IP";
	
	//MySQL user and password
	char* mysql_user = 	"Your Username";
	char* mysql_password = 	"Your Password";

	//Network Configuration
    	eth.set_dhcp(true);
    	eth.connect();
	
	//Socket Configuration
	tcpSocket.open(&eth);

	//MySQL Object declaration
	MySQL sql(&tcpSocket, server_ip);
	
	//Open MySQL session
	sql.connect(mysql_user, mysql_password);
	
	//Database typedef to store database info and table result
	TypeDef_Database* Database = NULL;

	while(true){
		//Get Table from Database
		Database = sql.query("SELECT * FROM database.table;",Database);

		//Print database over serial if something has been received
		if(Database!=NULL) sql.printDatabase(Database);

		//Make a simple query, if the query returns OK_PACKET form server, it returns true
		if(sql.query("INSERT INTO database.table VALUES(Your values);")){
			printf("Query OK !\r\n");
		}
		//Sleep for 5 seconds because c'mon let's chill
		ThisThread::sleep_for(5s);
	}
}
```
## Edit
### Use DNS
You can still resolve the MySQL server IP by resolving its IP address using [Mbed DNS Resolver](https://os.mbed.com/docs/mbed-os/v5.15/apis/dns-resolver.html).

Just use ```gethostbyname()``` (blocking) function.
### Configure the constants
```C++
const char* server_ip =	"Your MySQL Server IP";
char* mysql_user = 	"Your Username";
char* mysql_password = 	"Your Password";
```
## Run query
```C++
//Returns database typedef
TypeDef_Database* Database = sql.query("SELECT * FROM database.table;",Database);

//Returns boolean (true : OK_PACKET recieved, false : ERR_PACKET or EOF_PACKET RECIEVED)
bool query_answer = sql.query("INSERT INTO database.table VALUES(Your values);");
```
