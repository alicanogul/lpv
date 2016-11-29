Linux Password Vault

* Ali Can Oğul

INSTALLATION

* Install mysql DBMS with command "sudo apt-get install mysql-server",
  and set the db user password as 'codefellas'
* Connect the mysql server with command "mysql -u root -p",
  and initialize the database by copy/pasting the contents of init.sql
* Install necessary packages and libraries with:
  "sudo apt-get install build-essential ruby ruby-dev libmysqlclient-dev"
* Install necessary gems with command:
  "sudo gem install activerecord bcrypt mysql2"


USAGE

* Start SSL Server by using command:
  "ruby ssl_server.rb 9099 demoCA/cacert.pem demoCA/private/cakey.pem"
* Server certificate pass phrase is: test
* Start SSL client by using command:
  "ruby ssl_client.rb 9099 demoCA/cacert.pem"

COMMANDS

* adduser [username] [password] : Adds the user to the database.
* deluser [username] : Deletes the user from the database.
* changeuserpass [password] : Changes the logged in user's password.
* storepass [domain] [password] : Stores domain and its password to the database.
* getpass [domain] : Gets domain's password.
* changepass [domain] [password] : Changes domain's password.
* allow [username] [domain] : Allows specified user to access the specified domain's password.
* revokepass [username] [domain] : Revokes the specified user's access to the domain.
* removedom [domain] : Removes domain from database.
* addgroup [group name] : Adds the user group to the database.
* addtogroup [username] [group name] : Adds the user to the group.
* allowgroup [group name] [domain] : Allow all of the users of the group to access the domain's password.
* removefromgroup [username] [groupname] : Removes the specified user from the specified group.
* delgroup [group name] : Deletes the group from database.
* adjustglcaps [username] [feature] [boolean value] : Adjusts the specified user's capability to use the specified feature globally.
* adjustdomcaps [username] [domain] [feature] [boolean value] : Adjusts the specified user's capability to use the specified feature on the specified domain.
* adjustgroupcaps [username] [group name] [feature] [boolean value] : Adjusts the specified user's capability to use the specified feature on the specified group.
* quit: Quits the program.

WEBSITE

* http://senior.ceng.metu.edu.tr/2016/codefellas2/

