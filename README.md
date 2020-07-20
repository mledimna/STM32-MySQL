# STM32-MySQL
MySQL Client for STM32 using mbed library

# How to use this code ?
- Add the library to your mbed project (Right click on you project folder, and select **Add Library...**)
- Next you need to setup your network connection
- Create a TCP socket and initialize it
- Create a MySQL object by passing the initialized socket into the constructor argument

```C++
TypeDef_Database* Database = NULL; //To store database

EthernetInterface eth; //Network interface
TCPSocket sock; //TCP socket

//Initialize Network Here
//Initialize Socket Here

MySQL sql(&sock); //Construct the MySQL object

sql.connect("mysql_user", "mysql_password"); //Connect to database

Database = sql.query("SELECT * FROM database.table;",Database);
if(Database==NULL) printf("Database NULL after '%s'\r\n",query);
else sql.printDatabase(Database);
```
