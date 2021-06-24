# STM32-MySQL
MySQL Client for STM32 using [Mbed library](https://github.com/ARMmbed/mbed-os)

## Implement this code
- Add the library to your mbed project (Right click on you project folder, and select **Add Library...**)
- Setup your network connection
- Create a TCP socket and initialize it
- Create a MySQL object by passing the initialized socket into the constructor argument

## main.c Exeample
### Code (With DNS)
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

	while(true){
		//Get Table from Database
		if(sql.query("SELECT * FROM database.table;",Database)){
			//Print database over serial if something has been received
			sql.printDatabase(Database);
		}
		
		//Make a simple query, if the query returns OK_PACKET form server, it returns true
		if(sql.query("INSERT INTO database.table VALUES(Your values);")){
			printf("Query OK !\r\n");
		}
		
		//Sleep for 5 seconds because c'mon let's chill
		ThisThread::sleep_for(5s);
	}
}
```
